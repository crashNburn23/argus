"""IOC and relationship graph rendering — Rich Tree display and JSON export."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from rich.tree import Tree

from argus.cli.output import console

if TYPE_CHECKING:
    from argus.models.case import Case
    from argus.models.ioc import IOCEnrichmentRecord
    from argus.models.threat_actor import ThreatActor


# ---------------------------------------------------------------------------
# Core graph model
# ---------------------------------------------------------------------------


@dataclass
class GraphNode:
    id: str
    label: str
    node_type: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    label: str = ""


@dataclass
class Graph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, source_id: str, target_id: str, label: str = "") -> None:
        if source_id in self.nodes and target_id in self.nodes:
            self.edges.append(GraphEdge(source_id, target_id, label))

    @property
    def adjacency(self) -> dict[str, list[tuple[str, str]]]:
        adj: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for e in self.edges:
            adj[e.source_id].append((e.target_id, e.label))
        return dict(adj)

    def most_connected_root(self) -> str | None:
        if not self.nodes:
            return None
        counts: dict[str, int] = defaultdict(int)
        for e in self.edges:
            counts[e.source_id] += 2
            counts[e.target_id] += 1
        if not counts:
            return next(iter(self.nodes))
        return max(self.nodes, key=lambda k: counts.get(k, 0))

    def is_empty(self) -> bool:
        return not self.nodes


# ---------------------------------------------------------------------------
# Graph builders
# ---------------------------------------------------------------------------


def build_case_graph(case: Case) -> Graph:
    g = Graph()
    for obs in case.observables:
        g.add_node(
            GraphNode(
                id=obs.observable_id,
                label=obs.value[:60],
                node_type=obs.observable_type.value,
            )
        )
    for rel in case.relationships:
        g.add_edge(
            rel.source_ref,
            rel.target_ref,
            rel.relationship_type.value.replace("_", " "),
        )
    return g


def build_ioc_graph(record: IOCEnrichmentRecord) -> Graph:
    g = Graph()
    root_id = record.indicator
    g.add_node(GraphNode(id=root_id, label=root_id, node_type=str(record.ioc_type)))

    for dns in record.passive_dns[:10]:
        hostname = dns.get("hostname") or dns.get("domain") or dns.get("address") or ""
        hostname = str(hostname).strip()
        if hostname and hostname != root_id:
            ntype = "ip" if _is_ip(hostname) else "domain"
            g.add_node(GraphNode(id=hostname, label=hostname, node_type=ntype))
            g.add_edge(root_id, hostname, "resolves_to")

    for cert in record.ssl_certs[:5]:
        cert_id = str(cert.get("thumbprint") or cert.get("id") or cert.get("serial") or "")[:16]
        if not cert_id:
            continue
        cn = str(cert.get("subject") or cert.get("cn") or cert.get("name") or cert_id)[:40]
        node_id = f"cert:{cert_id}"
        g.add_node(GraphNode(id=node_id, label=f"cert {cn}", node_type="ssl_cert"))
        g.add_edge(root_id, node_id, "has_cert")
        for san in (cert.get("domains") or cert.get("sans") or [])[:5]:
            san = str(san).strip()
            if san and san != root_id:
                g.add_node(GraphNode(id=san, label=san, node_type="domain"))
                g.add_edge(node_id, san, "san")

    for infra in record.related_infrastructure[:8]:
        infra = str(infra).strip()
        if infra and infra != root_id:
            g.add_node(
                GraphNode(id=infra, label=infra, node_type="ip" if _is_ip(infra) else "domain")
            )
            g.add_edge(root_id, infra, "related_to")

    for actor in record.threat_actors[:4]:
        nid = f"actor:{actor}"
        g.add_node(GraphNode(id=nid, label=actor, node_type="actor"))
        g.add_edge(root_id, nid, "attributed_to")

    for mal in record.malware_families[:4]:
        nid = f"malware:{mal}"
        g.add_node(GraphNode(id=nid, label=mal, node_type="malware"))
        g.add_edge(root_id, nid, "associated_with")

    return g


def build_actor_graph(actor: ThreatActor) -> Graph:
    g = Graph()
    actor_id = f"actor:{actor.name}"
    g.add_node(GraphNode(id=actor_id, label=actor.name, node_type="actor"))

    for tech in actor.techniques[:12]:
        tid = tech.technique_id
        label = f"{tid} {tech.technique_name[:35]}"
        g.add_node(GraphNode(id=tid, label=label, node_type="ttp"))
        g.add_edge(actor_id, tid, "uses")

    for mal in actor.associated_malware[:6]:
        nid = f"malware:{mal}"
        g.add_node(GraphNode(id=nid, label=mal, node_type="malware"))
        g.add_edge(actor_id, nid, "uses")

    for camp in actor.campaigns[:4]:
        nid = f"campaign:{camp.name}"
        g.add_node(GraphNode(id=nid, label=camp.name[:40], node_type="campaign"))
        g.add_edge(actor_id, nid, "conducted")

    return g


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

_TYPE_STYLE: dict[str, str] = {
    "ip": "[cp.red]IP[/cp.red]",
    "domain": "[cp.cyan]DOM[/cp.cyan]",
    "url": "[cp.dim]URL[/cp.dim]",
    "md5": "[cp.amber]MD5[/cp.amber]",
    "sha1": "[cp.amber]SHA1[/cp.amber]",
    "sha256": "[cp.amber]SHA[/cp.amber]",
    "email": "[cp.magenta]EMAIL[/cp.magenta]",
    "actor": "[cp.red bold]ACTOR[/cp.red bold]",
    "malware": "[cp.amber bold]MAL[/cp.amber bold]",
    "ttp": "[cp.purple]TTP[/cp.purple]",
    "attack_ttp": "[cp.purple]TTP[/cp.purple]",
    "ssl_cert": "[cp.dim]CERT[/cp.dim]",
    "campaign": "[cp.green]CAMP[/cp.green]",
    "cve": "[cp.red]CVE[/cp.red]",
}


def _node_label(node: GraphNode) -> str:
    badge = _TYPE_STYLE.get(node.node_type, f"[cp.dim]{node.node_type[:4].upper()}[/cp.dim]")
    return f"{badge}  {node.label}"


def render_tree(graph: Graph, root_id: str | None = None, title: str = "Graph") -> None:
    if graph.is_empty():
        return

    adj = graph.adjacency
    root_id = root_id or graph.most_connected_root()
    if root_id is None or root_id not in graph.nodes:
        root_id = next(iter(graph.nodes))

    root_node = graph.nodes[root_id]
    tree = Tree(
        f"[cp.cyan]{title}[/cp.cyan]  {_node_label(root_node)}",
        guide_style="cp.border",
    )
    visited: set[str] = {root_id}
    _build_branch(tree, root_id, adj, graph.nodes, visited, depth=0)
    console.print(tree)


def _build_branch(
    branch: Tree,
    node_id: str,
    adj: dict[str, list[tuple[str, str]]],
    nodes: dict[str, GraphNode],
    visited: set[str],
    depth: int,
) -> None:
    if depth > 6:
        return
    for target_id, edge_label in adj.get(node_id, []):
        target = nodes.get(target_id)
        if target is None:
            continue
        edge_text = f"[cp.dim]{edge_label}[/cp.dim]  " if edge_label else ""
        if target_id in visited:
            branch.add(f"{edge_text}[cp.dim]↑ {target.label}[/cp.dim]")
        else:
            visited.add(target_id)
            child = branch.add(f"{edge_text}{_node_label(target)}")
            _build_branch(child, target_id, adj, nodes, visited, depth + 1)


def export_json(graph: Graph) -> str:
    return json.dumps(
        {
            "nodes": [
                {"id": n.id, "label": n.label, "type": n.node_type, "metadata": n.metadata}
                for n in graph.nodes.values()
            ],
            "edges": [
                {"source": e.source_id, "target": e.target_id, "label": e.label}
                for e in graph.edges
            ],
        },
        indent=2,
    )


def render_ioc_graph(record: IOCEnrichmentRecord) -> None:
    g = build_ioc_graph(record)
    if len(g.edges) == 0:
        return
    render_tree(g, root_id=record.indicator, title=f"Pivot: {record.indicator}")


def render_actor_graph(actor: ThreatActor) -> None:
    g = build_actor_graph(actor)
    if len(g.edges) == 0:
        return
    render_tree(g, root_id=f"actor:{actor.name}", title=f"Actor: {actor.name}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_ip(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))

import type { CaseGraphData } from './types'

export const GRAPH_NODE_WIDTH = 240
export const GRAPH_NODE_HEIGHT = 78

const COLUMN_GAP = 90
const ROW_GAP = 45

/**
 * Deterministic left-to-right layered layout for the case graph.
 *
 * Case graphs use fixed-size nodes and directed relationships, so a compact
 * topological layout is enough. Cyclic components share the first layer after
 * any acyclic predecessors, avoiding unbounded level propagation around cycles.
 */
export async function layoutCaseGraph(graph: CaseGraphData) {
  const ids = new Set(graph.nodes.map(node => node.id))
  const incoming = new Map<string, string[]>()
  const outgoing = new Map<string, string[]>()
  const indegree = new Map<string, number>()

  for (const id of ids) {
    incoming.set(id, [])
    outgoing.set(id, [])
    indegree.set(id, 0)
  }
  for (const edge of graph.edges) {
    if (!ids.has(edge.source) || !ids.has(edge.target) || edge.source === edge.target) continue
    outgoing.get(edge.source)?.push(edge.target)
    incoming.get(edge.target)?.push(edge.source)
    indegree.set(edge.target, (indegree.get(edge.target) ?? 0) + 1)
  }

  const levels = new Map<string, number>()
  const queue = [...ids].filter(id => indegree.get(id) === 0).sort()
  for (const id of queue) levels.set(id, 0)

  for (let index = 0; index < queue.length; index += 1) {
    const source = queue[index]
    const sourceLevel = levels.get(source) ?? 0
    for (const target of outgoing.get(source) ?? []) {
      levels.set(target, Math.max(levels.get(target) ?? 0, sourceLevel + 1))
      const remaining = (indegree.get(target) ?? 1) - 1
      indegree.set(target, remaining)
      if (remaining === 0) queue.push(target)
    }
  }

  const cyclicIds = [...ids].filter(id => !levels.has(id)).sort()
  const cyclicSet = new Set(cyclicIds)
  for (const id of cyclicIds) {
    const externalLevels = (incoming.get(id) ?? [])
      .filter(source => !cyclicSet.has(source))
      .map(source => levels.get(source) ?? 0)
    levels.set(id, externalLevels.length > 0 ? Math.max(...externalLevels) + 1 : 0)
  }

  const columns = new Map<number, typeof graph.nodes>()
  for (const node of graph.nodes) {
    const level = levels.get(node.id) ?? 0
    const column = columns.get(level) ?? []
    column.push(node)
    columns.set(level, column)
  }

  const positions = new Map<string, { x: number; y: number }>()
  for (const [level, nodes] of [...columns.entries()].sort(([a], [b]) => a - b)) {
    nodes.sort((a, b) => a.type.localeCompare(b.type) || a.label.localeCompare(b.label))
    nodes.forEach((node, row) => {
      positions.set(node.id, {
        x: level * (GRAPH_NODE_WIDTH + COLUMN_GAP),
        y: row * (GRAPH_NODE_HEIGHT + ROW_GAP),
      })
    })
  }

  return positions
}

import type { CaseGraphData } from './types'

export const GRAPH_NODE_WIDTH = 240
export const GRAPH_NODE_HEIGHT = 78

export async function layoutCaseGraph(graph: CaseGraphData) {
  const { default: ELK } = await import('elkjs/lib/elk.bundled.js')
  const elk = new ELK()
  const result = await elk.layout({
    id: 'root',
    layoutOptions: {
      'elk.algorithm': 'layered',
      'elk.direction': 'RIGHT',
      'elk.spacing.nodeNode': '45',
      'elk.layered.spacing.nodeNodeBetweenLayers': '90',
      'elk.layered.nodePlacement.strategy': 'NETWORK_SIMPLEX',
      'elk.edgeRouting': 'SPLINES',
      'elk.padding': '[top=40,left=40,bottom=40,right=40]',
    },
    children: graph.nodes.map(node => ({ id: node.id, width: GRAPH_NODE_WIDTH, height: GRAPH_NODE_HEIGHT })),
    edges: graph.edges.map(edge => ({ id: edge.id, sources: [edge.source], targets: [edge.target] })),
  })

  return new Map((result.children ?? []).map(node => [node.id, { x: node.x ?? 0, y: node.y ?? 0 }]))
}

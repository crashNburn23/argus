import { Handle, Position, type Node, type NodeProps } from '@xyflow/react'
import { cn } from '../../../lib/cn'
import type { GraphEntity } from './types'

export type CtiNodeData = { entity: GraphEntity } & Record<string, unknown>
export type CtiFlowNode = Node<CtiNodeData, 'cti'>

const accents: Record<string, string> = {
  case: 'border-zinc-400', ip: 'border-blue-500', domain: 'border-violet-500', url: 'border-indigo-500',
  sha256: 'border-amber-500', sha1: 'border-amber-500', md5: 'border-amber-500', cve: 'border-red-500',
  email: 'border-cyan-500', actor: 'border-emerald-500', malware: 'border-orange-500', attack_ttp: 'border-pink-500',
}

export default function CtiNode({ data, selected }: NodeProps<CtiFlowNode>) {
  const entity = data.entity
  return <div className={cn('w-[240px] rounded-xl border-l-4 border-y border-r bg-surface px-3 py-2.5 shadow-lg transition', accents[entity.type] ?? 'border-zinc-500', selected ? 'ring-2 ring-accent shadow-accent/20' : 'border-y-border border-r-border')}>
    <Handle type="target" position={Position.Left} className="!size-2 !border-background !bg-muted-foreground" />
    <div className="flex items-center justify-between gap-2"><span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] uppercase text-muted-foreground">{entity.type}</span>{entity.confidence > 0 && <span className="text-[10px] text-muted-foreground">{Math.round(entity.confidence * 100)}%</span>}</div>
    <div className="mt-2 truncate font-mono text-xs font-medium text-foreground" title={entity.label}>{entity.label}</div>
    <div className="mt-1 flex gap-1">{entity.manually_added && <span className="text-[10px] text-accent">manual</span>}{entity.argus_discovered && <span className="text-[10px] text-success">discovered</span>}</div>
    <Handle type="source" position={Position.Right} className="!size-2 !border-background !bg-muted-foreground" />
  </div>
}

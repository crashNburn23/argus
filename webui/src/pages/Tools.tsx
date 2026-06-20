import { useState } from 'react'
import { cn } from '../lib/cn'
import ErrorState from '../components/ErrorState'
import { useToolFile, useToolFiles } from '../features/tools/queries'

function availDot(available: boolean | null) {
  if (available === true) return 'bg-success'
  if (available === false) return 'bg-muted-foreground'
  return 'bg-border'
}

export default function Tools() {
  const [selected, setSelected] = useState<string | null>(null)
  const { data: files = [], isLoading, isError, refetch } = useToolFiles()
  const { data: fileContent, isFetching: loadingContent } = useToolFile(selected)

  const selectedFile = files.find(f => f.filename === selected)
  const lineCount = fileContent ? fileContent.content.split('\n').length : 0

  return (
    <div className="flex h-full overflow-hidden">
      {/* File list */}
      <div className="flex w-56 shrink-0 flex-col border-r border-border bg-surface">
        <div className="shrink-0 border-b border-border px-4 py-3">
          <h1 className="text-sm font-semibold text-foreground">Tool Source</h1>
          <p className="mt-0.5 text-xs text-muted-foreground">{files.length} files</p>
        </div>
        <div className="flex-1 overflow-y-auto">
          {isLoading && (
            <p className="px-4 py-3 text-xs text-muted-foreground">Loading…</p>
          )}
          {isError && (
            <div className="p-3">
              <ErrorState message="Failed to load tools" onRetry={refetch} />
            </div>
          )}
          {files.map(f => (
            <button
              key={f.filename}
              type="button"
              onClick={() => setSelected(f.filename)}
              className={cn(
                'w-full border-b border-border/50 px-4 py-2.5 text-left transition-colors hover:bg-surface-raised',
                selected === f.filename && 'bg-surface-raised',
              )}
            >
              <div className="flex items-center gap-2">
                <span className={cn('size-1.5 shrink-0 rounded-full', availDot(f.available))} />
                <span className="truncate font-mono text-sm text-foreground">{f.stem}</span>
              </div>
              {f.tool_names.length > 0 && (
                <p className="ml-3.5 mt-0.5 truncate text-xs text-muted-foreground">
                  {f.tool_names.join(', ')}
                </p>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Content panel */}
      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        {selected ? (
          <>
            <div className="shrink-0 flex items-center justify-between border-b border-border bg-surface px-4 py-3">
              <span className="font-mono text-sm text-foreground">{selected}</span>
              {fileContent && (
                <span className="text-xs text-muted-foreground">
                  {lineCount} lines · {Math.ceil((selectedFile?.size ?? 0) / 1024)}KB
                </span>
              )}
            </div>
            <div className="flex-1 overflow-auto">
              {loadingContent ? (
                <p className="p-4 text-xs text-muted-foreground">Loading…</p>
              ) : (
                <pre className="p-4 font-mono text-xs leading-relaxed text-foreground/80 whitespace-pre">
                  {fileContent?.content}
                </pre>
              )}
            </div>
          </>
        ) : (
          <div className="flex flex-1 items-center justify-center text-sm text-muted-foreground">
            Select a tool file to view its source
          </div>
        )}
      </div>
    </div>
  )
}

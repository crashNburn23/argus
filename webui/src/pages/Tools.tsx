import { useState, useEffect } from 'react'

interface ToolFile {
  filename: string
  stem: string
  tool_names: string[]
  available: boolean | null
  size: number
}

export default function Tools() {
  const [files, setFiles] = useState<ToolFile[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [content, setContent] = useState<string | null>(null)
  const [loadingFiles, setLoadingFiles] = useState(true)
  const [loadingContent, setLoadingContent] = useState(false)

  useEffect(() => {
    fetch('/api/tools/files')
      .then(r => r.json() as Promise<ToolFile[]>)
      .then(data => {
        setFiles(data)
        setLoadingFiles(false)
      })
      .catch(() => setLoadingFiles(false))
  }, [])

  const selectFile = (filename: string) => {
    if (filename === selected) return
    setSelected(filename)
    setContent(null)
    setLoadingContent(true)
    fetch(`/api/tools/files/${encodeURIComponent(filename)}`)
      .then(r => r.json() as Promise<{ filename: string; content: string }>)
      .then(data => {
        setContent(data.content)
        setLoadingContent(false)
      })
      .catch(() => {
        setContent('Error loading file.')
        setLoadingContent(false)
      })
  }

  const availDot = (available: boolean | null) => {
    if (available === null) return 'bg-zinc-600'
    return available ? 'bg-green-400' : 'bg-zinc-500'
  }

  const lineCount = content ? content.split('\n').length : 0

  return (
    <div className="flex h-full overflow-hidden">
      {/* File list panel */}
      <div className="w-56 flex-none border-r border-zinc-800 bg-zinc-900 flex flex-col">
        <div className="px-4 py-3 border-b border-zinc-800 flex-none">
          <h1 className="font-semibold text-sm text-zinc-100">Tool Source</h1>
          <p className="text-xs text-zinc-500 mt-0.5">{files.length} files</p>
        </div>
        <div className="flex-1 overflow-y-auto">
          {loadingFiles ? (
            <div className="px-4 py-3 text-xs text-zinc-500">Loading…</div>
          ) : (
            files.map(f => (
              <button
                key={f.filename}
                onClick={() => selectFile(f.filename)}
                className={`w-full text-left px-4 py-2.5 border-b border-zinc-800/50 hover:bg-zinc-800 transition-colors ${
                  selected === f.filename ? 'bg-zinc-800' : ''
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className={`w-1.5 h-1.5 rounded-full flex-none ${availDot(f.available)}`} />
                  <span className="text-sm text-zinc-200 font-mono truncate">{f.stem}</span>
                </div>
                {f.tool_names.length > 0 && (
                  <div className="ml-3.5 mt-0.5 text-xs text-zinc-500 truncate">
                    {f.tool_names.join(', ')}
                  </div>
                )}
              </button>
            ))
          )}
        </div>
      </div>

      {/* Content panel */}
      <div className="flex-1 overflow-hidden flex flex-col">
        {selected ? (
          <>
            <div className="flex-none px-4 py-3 border-b border-zinc-800 bg-zinc-900 flex items-center justify-between">
              <span className="font-mono text-sm text-zinc-200">{selected}</span>
              {content && (
                <span className="text-xs text-zinc-500">{lineCount} lines · {Math.ceil((files.find(f => f.filename === selected)?.size ?? 0) / 1024)}KB</span>
              )}
            </div>
            <div className="flex-1 overflow-auto">
              {loadingContent ? (
                <div className="p-4 text-xs text-zinc-500">Loading…</div>
              ) : (
                <pre className="p-4 text-xs font-mono text-zinc-300 leading-relaxed whitespace-pre">
                  {content}
                </pre>
              )}
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center text-zinc-600 text-sm">
            Select a tool file to view its source
          </div>
        )}
      </div>
    </div>
  )
}

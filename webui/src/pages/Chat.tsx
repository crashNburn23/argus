import { useState, useEffect, useRef, useCallback } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

interface ChatMessage {
  role: 'user' | 'assistant' | 'system'
  content: string
  streaming?: boolean
}

const STORAGE_KEY = 'argus-chat-global'

function loadMessages(): ChatMessage[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? (JSON.parse(raw) as ChatMessage[]) : []
  } catch {
    return []
  }
}

export default function Chat() {
  const [messages, setMessages] = useState<ChatMessage[]>(loadMessages)
  const [input, setInput] = useState('')
  const [connected, setConnected] = useState(false)
  const [running, setRunning] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const bottomRef = useRef<HTMLDivElement>(null)
  const progressRef = useRef('')

  useEffect(() => {
    const toSave = messages.filter(m => !m.streaming)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(toSave))
  }, [messages])

  const connect = useCallback(() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${proto}//${window.location.host}/api/chat/ws`)

    ws.onopen = () => setConnected(true)
    ws.onclose = () => {
      setConnected(false)
      setTimeout(connect, 3000)
    }
    ws.onerror = () => ws.close()

    ws.onmessage = (e: MessageEvent) => {
      const msg = JSON.parse(e.data as string) as { type: string; text: string }
      if (msg.type === 'progress') {
        progressRef.current += msg.text
        setMessages(prev => {
          const last = prev[prev.length - 1]
          if (last?.streaming) {
            return [...prev.slice(0, -1), { ...last, content: progressRef.current }]
          }
          return [...prev, { role: 'assistant', content: progressRef.current, streaming: true }]
        })
      } else if (msg.type === 'result') {
        progressRef.current = ''
        setMessages(prev => [
          ...prev.filter(m => !m.streaming),
          { role: 'assistant', content: msg.text },
        ])
        setRunning(false)
      } else if (msg.type === 'error' || msg.type === 'cancelled') {
        progressRef.current = ''
        setMessages(prev => [
          ...prev.filter(m => !m.streaming),
          { role: 'system', content: msg.text },
        ])
        setRunning(false)
      } else if (msg.type === 'cleared') {
        localStorage.removeItem(STORAGE_KEY)
        setMessages([])
        setRunning(false)
      }
    }

    wsRef.current = ws
  }, [])

  useEffect(() => {
    connect()
    return () => wsRef.current?.close()
  }, [connect])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const send = () => {
    const text = input.trim()
    if (!text || !connected || running) return
    setMessages(prev => [...prev, { role: 'user', content: text }])
    setInput('')
    setRunning(true)
    progressRef.current = ''
    wsRef.current?.send(JSON.stringify({ type: 'message', text, mode: 'global' }))
  }

  const cancel = () => wsRef.current?.send(JSON.stringify({ type: 'cancel' }))
  const clear = () => wsRef.current?.send(JSON.stringify({ type: 'clear' }))

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800 bg-zinc-900 flex-none">
        <h1 className="font-semibold text-zinc-100">Global Chat</h1>
        <div className="flex items-center gap-3">
          <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-400' : 'bg-red-400'}`} />
          <span className="text-xs text-zinc-400">{connected ? 'connected' : 'reconnecting…'}</span>
          <button
            onClick={clear}
            className="text-xs text-zinc-400 hover:text-zinc-200 px-2 py-1 rounded hover:bg-zinc-800 transition-colors"
          >
            clear
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.length === 0 && (
          <div className="text-center text-zinc-600 text-sm mt-16">
            Ask Argus anything about threats, IOCs, or CTI analysis.
          </div>
        )}
        {messages.map((m, i) => (
          <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div
              className={`max-w-3xl rounded-lg px-4 py-3 text-sm ${
                m.role === 'user'
                  ? 'bg-blue-600 text-white'
                  : m.role === 'system'
                    ? 'bg-zinc-800 text-zinc-400 italic'
                    : 'bg-zinc-800 text-zinc-100'
              }`}
            >
              {m.role === 'user' ? (
                <span className="whitespace-pre-wrap">{m.content}</span>
              ) : (
                <div className="prose prose-invert prose-sm max-w-none">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{m.content}</ReactMarkdown>
                </div>
              )}
              {m.streaming && <span className="animate-pulse ml-1 text-zinc-400">▋</span>}
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      <div className="flex-none p-4 border-t border-zinc-800 bg-zinc-900">
        <div className="flex gap-2">
          <textarea
            className="flex-1 bg-zinc-800 text-zinc-100 rounded-lg px-3 py-2 text-sm resize-none outline-none border border-zinc-700 focus:border-blue-500 transition-colors"
            rows={2}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault()
                send()
              }
            }}
            placeholder="Ask Argus anything… (Shift+Enter for newline)"
            disabled={!connected}
          />
          {running ? (
            <button
              onClick={cancel}
              className="px-4 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-medium transition-colors"
            >
              Stop
            </button>
          ) : (
            <button
              onClick={send}
              disabled={!connected || !input.trim()}
              className="px-4 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white rounded-lg text-sm font-medium transition-colors"
            >
              Send
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

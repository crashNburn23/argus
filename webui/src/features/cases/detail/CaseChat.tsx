import { useCallback, useEffect, useRef, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { useQueryClient } from '@tanstack/react-query'
import Button from '../../../components/ui/Button'
import Textarea from '../../../components/ui/Textarea'
import { caseDetailKey } from './queries'
import type { ChatMessage } from './types'

function loadMessages(storageKey: string): ChatMessage[] {
  try {
    const raw = localStorage.getItem(storageKey)
    return raw ? (JSON.parse(raw) as ChatMessage[]) : []
  } catch {
    return []
  }
}

export default function CaseChat({ caseId }: { caseId: string }) {
  const queryClient = useQueryClient()
  const storageKey = `argus-chat-case-${caseId}`
  const [messages, setMessages] = useState<ChatMessage[]>(() => loadMessages(storageKey))
  const [input, setInput] = useState('')
  const [connected, setConnected] = useState(false)
  const [running, setRunning] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimerRef = useRef<number>()
  const mountedRef = useRef(true)
  const progressRef = useRef('')
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    localStorage.setItem(storageKey, JSON.stringify(messages.filter(m => !m.streaming)))
  }, [messages, storageKey])

  const connect = useCallback(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const socket = new WebSocket(`${protocol}//${window.location.host}/api/chat/ws`)
    wsRef.current = socket

    socket.onopen = () => setConnected(true)
    socket.onerror = () => socket.close()
    socket.onclose = () => {
      setConnected(false)
      if (mountedRef.current) reconnectTimerRef.current = window.setTimeout(connect, 3_000)
    }
    socket.onmessage = (event: MessageEvent) => {
      const msg = JSON.parse(event.data as string) as { type: string; text: string }
      if (msg.type === 'progress') {
        progressRef.current += msg.text
        setMessages(prev => {
          const last = prev[prev.length - 1]
          const streaming = { role: 'assistant' as const, content: progressRef.current, streaming: true }
          return last?.streaming ? [...prev.slice(0, -1), streaming] : [...prev, streaming]
        })
      } else if (msg.type === 'result') {
        progressRef.current = ''
        const content = msg.text.trim()
        setMessages(prev => [
          ...prev.filter(m => !m.streaming),
          content
            ? { role: 'assistant', content }
            : { role: 'system', content: 'Argus completed, but no response text was returned.' },
        ])
        setRunning(false)
        void queryClient.invalidateQueries({ queryKey: caseDetailKey(caseId) })
      } else if (msg.type === 'error' || msg.type === 'cancelled') {
        progressRef.current = ''
        setMessages(prev => [
          ...prev.filter(m => !m.streaming),
          { role: 'system', content: msg.text },
        ])
        setRunning(false)
      }
    }
  }, [caseId, queryClient])

  useEffect(() => {
    mountedRef.current = true
    connect()
    return () => {
      mountedRef.current = false
      window.clearTimeout(reconnectTimerRef.current)
      wsRef.current?.close()
    }
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
    wsRef.current?.send(JSON.stringify({ type: 'message', text, mode: 'case', case_id: caseId }))
  }

  return (
    <div className="flex h-full flex-col bg-background">
      <div className="flex-1 space-y-4 overflow-y-auto p-4 sm:p-6">
        {messages.length === 0 && (
          <p className="mt-12 text-center text-sm text-muted-foreground">
            Ask Argus about this case. Responses are automatically saved as notes.
          </p>
        )}
        {messages.map((message, index) => (
          <div key={index} className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div
              className={`max-w-3xl rounded-xl px-4 py-3 text-sm ${
                message.role === 'user'
                  ? 'bg-accent text-accent-foreground'
                  : message.role === 'system'
                    ? 'border border-border bg-muted text-muted-foreground italic'
                    : 'border border-border bg-surface text-foreground'
              }`}
            >
              {message.role === 'user' ? (
                <span className="whitespace-pre-wrap">{message.content}</span>
              ) : (
                <div className="prose prose-invert prose-sm max-w-none">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{message.content}</ReactMarkdown>
                </div>
              )}
              {message.streaming && (
                <span className="ml-1 animate-pulse text-muted-foreground">▋</span>
              )}
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      <div className="shrink-0 border-t border-border bg-surface p-4">
        <div className="mb-2 flex items-center gap-2 text-xs text-muted-foreground">
          <span className={`size-2 rounded-full ${connected ? 'bg-success' : 'bg-danger'}`} />
          {connected ? 'Connected' : 'Reconnecting…'}
        </div>
        <div className="flex items-end gap-2">
          <Textarea
            className="min-h-[4.25rem] flex-1 resize-none"
            rows={2}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault()
                send()
              }
            }}
            placeholder="Ask about this case…"
            disabled={!connected}
          />
          {running ? (
            <Button
              variant="danger"
              onClick={() => wsRef.current?.send(JSON.stringify({ type: 'cancel' }))}
            >
              Stop
            </Button>
          ) : (
            <Button onClick={send} disabled={!connected || !input.trim()}>
              Send
            </Button>
          )}
        </div>
      </div>
    </div>
  )
}

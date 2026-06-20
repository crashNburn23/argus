import { useEffect, useRef, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import PageHeader from '../components/PageHeader'
import Button from '../components/ui/Button'
import Textarea from '../components/ui/Textarea'
import { useGlobalChat } from '../features/chat/useGlobalChat'

export default function Chat() {
  const [input, setInput] = useState('')
  const { messages, connected, running, send, cancel, clear } = useGlobalChat()
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const handleSend = () => {
    const text = input.trim()
    if (!text) return
    send(text)
    setInput('')
  }

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Chat"
        description="Ask about threat actors, CVEs, IOCs, or paste a URL to analyze."
        actions={
          <Button
            variant="ghost"
            size="sm"
            onClick={clear}
            disabled={running || messages.length === 0}
          >
            Clear history
          </Button>
        }
      />

      <div className="flex-1 space-y-4 overflow-y-auto p-4 sm:p-6">
        {messages.length === 0 && (
          <p className="mt-12 text-center text-sm text-muted-foreground">
            No messages yet. Ask about a threat actor, CVE, or IOC — or paste a URL to analyze a report.
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
                handleSend()
              }
            }}
            placeholder="Ask Argus anything… (Shift+Enter for newline)"
            disabled={!connected}
          />
          {running ? (
            <Button variant="danger" onClick={cancel}>Stop</Button>
          ) : (
            <Button onClick={handleSend} disabled={!connected || !input.trim()}>Send</Button>
          )}
        </div>
      </div>
    </div>
  )
}

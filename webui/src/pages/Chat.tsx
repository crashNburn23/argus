import { useEffect, useRef, useState } from 'react'
import { ArrowRight, RefreshCw, Settings } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Link } from 'react-router-dom'
import PageHeader from '../components/PageHeader'
import Button from '../components/ui/Button'
import Textarea from '../components/ui/Textarea'
import { useGlobalChat } from '../features/chat/useGlobalChat'

export default function Chat() {
  const [input, setInput] = useState('')
  const { messages, connected, running, send, cancel, clear, reconnect } = useGlobalChat()
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
        {messages.length === 0 && <ChatEmptyState onSelect={setInput} />}
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
        <div className="mb-2 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <span className={`size-2 rounded-full ${connected ? 'bg-success' : 'bg-danger'}`} />
          <span>{connected ? 'Connected' : 'Chat service unavailable'}</span>
          {!connected && <>
            <button type="button" onClick={reconnect} className="ml-1 inline-flex items-center gap-1 font-medium text-accent hover:underline"><RefreshCw className="size-3" aria-hidden="true" />Retry</button>
            <Link to="/settings" className="inline-flex items-center gap-1 font-medium text-accent hover:underline"><Settings className="size-3" aria-hidden="true" />Settings</Link>
          </>}
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

const STARTERS = [
  ['Investigate an IOC', 'Investigate this IOC and summarize reputation, infrastructure, and related threats: '],
  ['Research a threat actor', 'Research this threat actor, including recent campaigns, TTPs, and attributed infrastructure: '],
  ['Analyze a report URL', 'Analyze this threat intelligence report and extract key findings, IOCs, and TTPs: '],
  ['Assess a CVE', 'Assess this CVE for severity, exploitation status, affected products, and remediation priority: CVE-'],
] as const

function ChatEmptyState({ onSelect }: { onSelect: (value: string) => void }) {
  return <div className="mx-auto mt-8 max-w-2xl rounded-xl border border-border bg-surface p-5 sm:mt-12 sm:p-6">
    <h2 className="font-semibold text-foreground">Start an intelligence task</h2>
    <p className="mt-1 text-sm text-muted-foreground">Choose a starting point or write a custom request below.</p>
    <div className="mt-4 grid gap-2 sm:grid-cols-2">
      {STARTERS.map(([label, prompt]) => <button key={label} type="button" onClick={() => onSelect(prompt)} className="group flex items-center justify-between gap-3 rounded-lg border border-border bg-background px-3 py-3 text-left text-sm text-foreground hover:border-accent/50 hover:bg-surface-raised">
        <span>{label}</span><ArrowRight className="size-4 shrink-0 text-muted-foreground group-hover:text-accent" aria-hidden="true" />
      </button>)}
    </div>
  </div>
}

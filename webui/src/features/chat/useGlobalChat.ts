import { useCallback, useEffect, useRef, useState } from 'react'

export interface ChatMessage {
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

export function useGlobalChat() {
  const [messages, setMessages] = useState<ChatMessage[]>(loadMessages)
  const [connected, setConnected] = useState(false)
  const [running, setRunning] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimerRef = useRef<number>()
  const mountedRef = useRef(true)
  const progressRef = useRef('')

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(messages.filter(m => !m.streaming)))
  }, [messages])

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN || wsRef.current?.readyState === WebSocket.CONNECTING) return
    window.clearTimeout(reconnectTimerRef.current)
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
      } else if (msg.type === 'error' || msg.type === 'cancelled') {
        progressRef.current = ''
        setMessages(prev => [...prev.filter(m => !m.streaming), { role: 'system', content: msg.text }])
        setRunning(false)
      } else if (msg.type === 'cleared') {
        localStorage.removeItem(STORAGE_KEY)
        setMessages([])
        setRunning(false)
      }
    }
  }, [])

  useEffect(() => {
    mountedRef.current = true
    connect()
    return () => {
      mountedRef.current = false
      window.clearTimeout(reconnectTimerRef.current)
      wsRef.current?.close()
    }
  }, [connect])

  const send = (text: string) => {
    if (!text.trim() || !connected || running) return
    setMessages(prev => [...prev, { role: 'user', content: text }])
    setRunning(true)
    progressRef.current = ''
    wsRef.current?.send(JSON.stringify({ type: 'message', text, mode: 'global' }))
  }

  const cancel = () => wsRef.current?.send(JSON.stringify({ type: 'cancel' }))
  const clear = () => wsRef.current?.send(JSON.stringify({ type: 'clear' }))
  const reconnect = () => connect()

  return { messages, connected, running, send, cancel, clear, reconnect }
}

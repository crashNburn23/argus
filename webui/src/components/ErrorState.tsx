import { AlertTriangle } from 'lucide-react'

interface ErrorStateProps {
  title?: string
  message: string
  onRetry?: () => void
}

export default function ErrorState({ title = 'Something went wrong', message, onRetry }: ErrorStateProps) {
  return (
    <div role="alert" className="flex min-h-52 flex-col items-center justify-center rounded-xl border border-danger/30 bg-danger/5 px-6 py-10 text-center">
      <AlertTriangle className="mb-3 size-5 text-danger" aria-hidden="true" />
      <h2 className="text-sm font-medium text-foreground">{title}</h2>
      <p className="mt-1 max-w-md text-sm text-muted-foreground">{message}</p>
      {onRetry && (
        <button type="button" onClick={onRetry} className="mt-4 rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-foreground hover:bg-surface-raised">
          Try again
        </button>
      )}
    </div>
  )
}

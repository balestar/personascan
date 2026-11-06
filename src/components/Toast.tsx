import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'

export type ToastTone = 'success' | 'error' | 'info'

export type ToastItem = {
  id: string
  message: string
  tone: ToastTone
}

type Props = {
  toasts: ToastItem[]
  onDismiss: (id: string) => void
}

export function ToastStack({ toasts, onDismiss }: Props) {
  if (typeof document === 'undefined' || !toasts.length) return null
  return createPortal(
    <div className="toast-stack" role="region" aria-label="Notifications" aria-live="polite">
      {toasts.map((t) => (
        <ToastCard key={t.id} item={t} onDismiss={onDismiss} />
      ))}
    </div>,
    document.body,
  )
}

function ToastCard({ item, onDismiss }: { item: ToastItem; onDismiss: (id: string) => void }) {
  useEffect(() => {
    const ms = item.tone === 'error' ? 8000 : 4500
    const id = window.setTimeout(() => onDismiss(item.id), ms)
    return () => window.clearTimeout(id)
  }, [item.id, item.tone, onDismiss])

  return (
    <div className={`toast toast--${item.tone}`} role="status">
      <p>{item.message}</p>
      <button type="button" className="toast__x" aria-label="Dismiss" onClick={() => onDismiss(item.id)}>
        ×
      </button>
    </div>
  )
}

export function useToasts() {
  const [toasts, setToasts] = useState<ToastItem[]>([])

  function push(message: string, tone: ToastTone = 'info') {
    const id = `toast_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`
    setToasts((prev) => [...prev.slice(-4), { id, message, tone }])
    return id
  }

  function dismiss(id: string) {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }

  return {
    toasts,
    dismiss,
    success: (message: string) => push(message, 'success'),
    error: (message: string) => push(message, 'error'),
    info: (message: string) => push(message, 'info'),
  }
}

import { useEffect, useId, useRef } from 'react'
import type { ReactNode } from 'react'

type SheetProps = {
  open: boolean
  onClose: () => void
  title: string
  subtitle?: string
  children: ReactNode
  footer?: ReactNode
  /** vault = dark green (scan + admin); admin kept for legacy light forms */
  variant?: 'vault' | 'admin'
  size?: 'default' | 'wide'
}

export function Sheet({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
  variant = 'vault',
  size = 'default',
}: SheetProps) {
  const titleId = useId()
  const panelRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const t = window.setTimeout(() => {
      panelRef.current
        ?.querySelector<HTMLElement>('.ps-dialog__x, button, [href], input, select, textarea')
        ?.focus()
    }, 40)
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => {
      window.clearTimeout(t)
      document.body.style.overflow = prev
      window.removeEventListener('keydown', onKey)
    }
  }, [open, onClose])

  if (!open) return null

  return (
    <div className={`ps-overlay ps-overlay--${variant}`} role="presentation">
      <button type="button" className="ps-overlay__dim" aria-label="Close dialog" onClick={onClose} />
      <div
        ref={panelRef}
        className={`ps-dialog ${size === 'wide' ? 'ps-dialog--wide' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="ps-dialog__chrome">
          <div className="ps-dialog__handle" aria-hidden />
          <header className="ps-dialog__head">
            <div className="ps-dialog__titles">
              <h2 id={titleId}>{title}</h2>
              {subtitle ? <p>{subtitle}</p> : null}
            </div>
            <button type="button" className="ps-dialog__x" onClick={onClose} aria-label="Close">
              <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden>
                <path
                  d="M2 2l10 10M12 2L2 12"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                />
              </svg>
            </button>
          </header>
          <div className="ps-dialog__body">{children}</div>
          {footer ? <footer className="ps-dialog__foot">{footer}</footer> : null}
        </div>
      </div>
    </div>
  )
}

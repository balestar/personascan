import { Sheet } from './Sheet'
import type { ReactNode } from 'react'

type ModalProps = {
  title: string
  subtitle?: string
  open: boolean
  onClose: () => void
  children: ReactNode
  wide?: boolean
  footer?: ReactNode
  /** Match admin console dark theme by default */
  variant?: 'vault' | 'admin'
}

export function Modal({
  title,
  subtitle,
  open,
  onClose,
  children,
  footer,
  wide,
  variant = 'vault',
}: ModalProps) {
  return (
    <Sheet
      open={open}
      onClose={onClose}
      title={title}
      subtitle={subtitle}
      footer={footer}
      variant={variant}
      size={wide ? 'wide' : 'default'}
    >
      {children}
    </Sheet>
  )
}

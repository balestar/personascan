import { useEffect, useMemo, useState } from 'react'
import { sendInviteEmail } from '../lib/api'
import { blankCustomEmail, oneTimeScanTemplate } from '../lib/emailTemplates'
import type { UserRecord } from '../types'
import { Modal } from './Modal'

type Props = {
  open: boolean
  user: UserRecord | null
  link: string
  onClose: () => void
}

function customPreviewHtml(subject: string, body: string) {
  const safe = body
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('\n', '<br/>')
  return `<!DOCTYPE html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/></head>
<body style="margin:0;padding:24px;background:#07110e;font-family:Segoe UI,Helvetica,Arial,sans-serif;color:#e8f6ef;">
  <div style="max-width:520px;margin:0 auto;background:#0d1a15;border:1px solid rgba(124,255,178,0.18);border-radius:16px;padding:22px;">
    <div style="font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:#7cffb2;font-weight:700;margin-bottom:10px;">Preview</div>
    <h1 style="margin:0 0 14px;font-size:18px;color:#f4fff8;">${subject
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')}</h1>
    <div style="font-size:14px;line-height:1.55;color:#cfe9dc;">${safe}</div>
  </div>
</body></html>`
}

export function EmailModal({ open, user, link, onClose }: Props) {
  const [mode, setMode] = useState<'template' | 'custom'>('template')
  const [subject, setSubject] = useState('')
  const [body, setBody] = useState('')
  const [notice, setNotice] = useState('')
  const [sending, setSending] = useState(false)

  const template = useMemo(() => {
    if (!user) return null
    return oneTimeScanTemplate({
      name: user.name,
      link,
      country: user.country,
      expiresAt: user.linkExpiresAt,
    })
  }, [user, link])

  useEffect(() => {
    if (!open || !user) return
    setMode('template')
    setNotice('')
    const draft = oneTimeScanTemplate({
      name: user.name,
      link,
      country: user.country,
      expiresAt: user.linkExpiresAt,
    })
    setSubject(draft.subject)
    setBody(draft.body)
  }, [open, user, link])

  function applyMode(next: 'template' | 'custom') {
    if (!user) return
    setMode(next)
    setNotice('')
    if (next === 'template') {
      const draft = oneTimeScanTemplate({
        name: user.name,
        link,
        country: user.country,
        expiresAt: user.linkExpiresAt,
      })
      setSubject(draft.subject)
      setBody(draft.body)
    } else {
      const draft = blankCustomEmail({ name: user.name, link })
      setSubject(draft.subject)
      setBody(draft.body)
    }
  }

  const previewHtml = useMemo(() => {
    if (mode === 'template' && template) return template.html
    return customPreviewHtml(subject, body)
  }, [mode, template, subject, body])

  async function copyBody() {
    await navigator.clipboard.writeText(body)
    setNotice('Message text copied.')
  }

  async function copyHtml() {
    await navigator.clipboard.writeText(previewHtml)
    setNotice('HTML copied.')
  }

  function openMailClient() {
    if (!user) return
    const href = `mailto:${encodeURIComponent(user.email)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`
    window.location.href = href
    setNotice('Opening mail client…')
  }

  async function sendEmail() {
    if (!user || sending) return
    setSending(true)
    setNotice('')
    try {
      const result = await sendInviteEmail({
        to: user.email,
        subject,
        html: previewHtml,
        text: body,
      })
      setNotice(`Sent from ${result.from}`)
    } catch (err) {
      setNotice(err instanceof Error ? err.message : 'Send failed')
    } finally {
      setSending(false)
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      wide
      variant="vault"
      title="Compose invitation"
      subtitle={user ? `${user.name} · ${user.email}` : undefined}
      footer={
        <div className="vault-sheet-actions vault-sheet-actions--triple">
          <button type="button" className="vault-btn vault-btn-ghost" onClick={() => void copyBody()}>
            Copy text
          </button>
          <button type="button" className="vault-btn vault-btn-ghost" onClick={openMailClient} disabled={!user}>
            Open mail app
          </button>
          <button
            type="button"
            className="vault-btn vault-btn-glow"
            onClick={() => void sendEmail()}
            disabled={!user || sending}
          >
            {sending ? 'Sending…' : 'Send email'}
          </button>
        </div>
      }
    >
      {!user ? (
        <p className="vault-hint">No recipient selected.</p>
      ) : (
        <div className="mail-compose">
          <div className="mail-seg" role="tablist" aria-label="Email type">
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'template'}
              className={mode === 'template' ? 'is-active' : ''}
              onClick={() => applyMode('template')}
            >
              Scan template
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'custom'}
              className={mode === 'custom' ? 'is-active' : ''}
              onClick={() => applyMode('custom')}
            >
              Custom
            </button>
          </div>

          <div className="mail-grid">
            <section className="mail-editor" aria-label="Compose">
              <label className="mail-field">
                <span>To</span>
                <input value={user.email} readOnly />
              </label>
              <label className="mail-field">
                <span>Subject</span>
                <input value={subject} onChange={(e) => setSubject(e.target.value)} />
              </label>
              <label className="mail-field mail-field--grow">
                <span>Message</span>
                <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={12} />
              </label>
              <p className="mail-hint">
                From noreply@personascan.net · private one-time link · 20-minute session
              </p>
              {notice ? <p className="mail-notice">{notice}</p> : null}
            </section>

            <section className="mail-preview" aria-label="Email preview">
              <div className="mail-preview-head">
                <strong>Live preview</strong>
                <span>{mode === 'template' ? 'HTML template' : 'Plain message'}</span>
              </div>
              <iframe title="Email preview" className="mail-frame" srcDoc={previewHtml} sandbox="" />
            </section>
          </div>
        </div>
      )}
    </Modal>
  )
}

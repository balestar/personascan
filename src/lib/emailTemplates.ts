export type EmailDraft = {
  subject: string
  body: string
  html: string
}

export function oneTimeScanTemplate(input: {
  name: string
  link: string
  country: string
  expiresAt?: string
}): EmailDraft {
  const first = input.name.split(' ')[0] || input.name
  const expires = input.expiresAt
    ? new Date(input.expiresAt).toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      })
    : '20 minutes after issue'

  const subject = 'Your secured Persona Scan invitation'
  const body = `Hello ${first},

You have been invited to complete a one-time secured device threat scan with Persona Scan.

Private link (do not share):
${input.link}

What to expect
• Open the link on the device you want checked
• Review and accept the scan terms
• Run the live device probes and review your scored results

Session validity: 20 minutes (expires ${expires})

If you did not expect this invitation, ignore this message.

—
Persona Scan
https://personascan.net
Confidential · One-time access`

  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${subject}</title>
</head>
<body style="margin:0;padding:0;background:#07110e;font-family:'Segoe UI',Helvetica,Arial,sans-serif;color:#e8f6ef;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#07110e;padding:32px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:560px;background:#0d1a15;border:1px solid rgba(124,255,178,0.18);border-radius:18px;overflow:hidden;">
          <tr>
            <td style="padding:28px 28px 12px;background:linear-gradient(135deg,#0d1a15,#123528);">
              <div style="font-size:13px;letter-spacing:0.14em;text-transform:uppercase;color:#7cffb2;font-weight:700;">Persona Scan</div>
              <h1 style="margin:12px 0 0;font-size:26px;line-height:1.2;color:#f4fff8;">One-time device threat scan</h1>
            </td>
          </tr>
          <tr>
            <td style="padding:8px 28px 24px;color:#8eab9c;font-size:15px;line-height:1.6;">
              <p style="margin:0 0 16px;color:#e8f6ef;">Hello ${escapeHtml(first)},</p>
              <p style="margin:0 0 16px;">You have a private invitation to complete your <strong style="color:#7cffb2;">one-time secured scan</strong> for threats including IP leaks, password exposure, opaque APIs, personal-data apps, ads SDKs, bots, and cryptographic posture.</p>
              <p style="margin:0 0 22px;">This one-time session remains valid for <strong style="color:#e8f6ef;">20 minutes</strong> (until ${escapeHtml(expires)}).</p>
              <p style="margin:0 0 28px;text-align:center;">
                <a href="${escapeAttr(input.link)}" style="display:inline-block;background:linear-gradient(135deg,#7cffb2,#2bd4a8);color:#04140f;text-decoration:none;font-weight:700;padding:14px 22px;border-radius:999px;">Start secured scan</a>
              </p>
              <p style="margin:0 0 8px;font-size:12px;word-break:break-all;color:#8eab9c;">Or paste this link:<br/><a href="${escapeAttr(input.link)}" style="color:#7cffb2;">${escapeHtml(input.link)}</a></p>
              <hr style="border:none;border-top:1px solid rgba(124,255,178,0.14);margin:22px 0;" />
              <p style="margin:0;font-size:12px;color:#6f8b7d;">Persona Scan scans are secure. No software install is required. Do not forward this invitation.</p>
            </td>
          </tr>
        </table>
        <p style="margin:18px 0 0;font-size:12px;color:#6f8b7d;">personascan.net</p>
      </td>
    </tr>
  </table>
</body>
</html>`

  return { subject, body, html }
}

export function blankCustomEmail(input: { name: string; link: string }): EmailDraft {
  const first = input.name.split(' ')[0] || input.name
  return {
    subject: 'Your Persona Scan invitation',
    body: `Hello ${first},\n\n${input.link}\n\n—\nPersona Scan`,
    html: `<p>Hello ${escapeHtml(first)},</p><p><a href="${escapeAttr(input.link)}">${escapeHtml(input.link)}</a></p><p>— Persona Scan</p>`,
  }
}

function escapeHtml(value: string) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
}

function escapeAttr(value: string) {
  return escapeHtml(value).replaceAll("'", '&#39;')
}

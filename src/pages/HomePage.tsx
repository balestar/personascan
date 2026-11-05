import { Link } from 'react-router-dom'
import { BrandMark } from '../components/BrandMark'

export function HomePage() {
  return (
    <div className="page home-page">
      <div className="atmosphere" aria-hidden />
      <header className="site-header">
        <Link to="/" className="brand-lockup">
          <BrandMark size="sm" />
          <span>Persona Scan</span>
        </Link>
        <Link className="ghost-link" to="/admin">
          Admin
        </Link>
      </header>

      <main className="home-hero">
        <p className="brand-wordmark">Persona Scan</p>
        <h1>Device threat scans, delivered by secured link.</h1>
        <p className="lede">
          Invite someone by name, email, and country. Generate a one-time secure link. They open it,
          accept the terms, and fetch a full privacy threat report.
        </p>
        <div className="cta-row">
          <Link className="btn btn-primary" to="/admin">
            Open admin console
          </Link>
          <a className="btn btn-ghost" href="https://personascan.net" rel="noreferrer">
            personascan.net
          </a>
        </div>
      </main>
    </div>
  )
}

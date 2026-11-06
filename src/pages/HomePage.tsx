import { Link } from 'react-router-dom'
import { BrandMark } from '../components/BrandMark'

export function HomePage() {
  return (
    <div className="home-page">
      <div className="home-atmosphere" aria-hidden>
        <span className="home-grid" />
        <span className="home-glow" />
      </div>

      <header className="home-topbar">
        <Link to="/" className="home-brand" aria-label="Persona Scan">
          <BrandMark size="sm" />
        </Link>
        <Link className="home-nav-link" to="/admin">
          Admin
        </Link>
      </header>

      <main className="home-hero">
        <p className="home-kicker">Device security</p>
        <h1 className="home-title">Persona Scan</h1>
        <p className="home-lede">
          One-time secured device threat scans — invite by email, open a private link, get live
          scored results.
        </p>
        <Link className="home-cta" to="/admin">
          Open admin console
        </Link>
        <p className="home-domain">personascan.net</p>
      </main>
    </div>
  )
}

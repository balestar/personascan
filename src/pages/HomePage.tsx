import { Link } from 'react-router-dom'
import { BrandMark } from '../components/BrandMark'

export function HomePage() {
  return (
    <div className="home-page">
      <div className="home-atmosphere" aria-hidden>
        <span className="home-blob home-blob--a" />
        <span className="home-blob home-blob--b" />
        <span className="home-blob home-blob--c" />
        <svg className="home-web" viewBox="0 0 1200 800" preserveAspectRatio="xMidYMid slice">
          <g stroke="currentColor" strokeWidth="1" fill="none" opacity="0.55">
            <path d="M80 120L260 200L420 90L610 180L780 110L980 210L1120 140" />
            <path d="M120 420L290 360L470 480L650 390L820 520L1010 430L1140 510" />
            <path d="M60 680L240 600L430 720L620 610L800 700L990 620L1160 690" />
            <path d="M260 200L290 360L430 720" />
            <path d="M420 90L470 480L620 610" />
            <path d="M610 180L650 390L800 700" />
            <path d="M780 110L820 520L990 620" />
            <path d="M980 210L1010 430L1140 510" />
          </g>
          <g fill="currentColor">
            <circle cx="80" cy="120" r="4" />
            <circle cx="260" cy="200" r="5" />
            <circle cx="420" cy="90" r="4" />
            <circle cx="610" cy="180" r="6" />
            <circle cx="780" cy="110" r="4" />
            <circle cx="980" cy="210" r="5" />
            <circle cx="1120" cy="140" r="4" />
            <circle cx="120" cy="420" r="4" />
            <circle cx="290" cy="360" r="5" />
            <circle cx="470" cy="480" r="4" />
            <circle cx="650" cy="390" r="6" />
            <circle cx="820" cy="520" r="4" />
            <circle cx="1010" cy="430" r="5" />
            <circle cx="240" cy="600" r="4" />
            <circle cx="430" cy="720" r="5" />
            <circle cx="620" cy="610" r="4" />
            <circle cx="800" cy="700" r="5" />
            <circle cx="990" cy="620" r="4" />
          </g>
        </svg>
      </div>

      <header className="home-topbar">
        <Link to="/" className="home-brand">
          <BrandMark size="sm" />
          <span>Persona Scan</span>
        </Link>
        <Link className="home-nav-link" to="/admin">
          Admin
        </Link>
      </header>

      <main className="home-hero">
        <div className="home-hero-mark">
          <BrandMark size="lg" />
        </div>
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

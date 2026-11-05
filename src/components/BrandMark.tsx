export function BrandMark({ size = 'md' }: { size?: 'sm' | 'md' | 'lg' }) {
  const dim = size === 'lg' ? 48 : size === 'sm' ? 28 : 36
  return (
    <div className={`brand-mark brand-mark--${size}`} aria-hidden>
      <svg width={dim} height={dim} viewBox="0 0 48 48" fill="none">
        <rect x="2" y="2" width="44" height="44" rx="12" fill="url(#ps-grad)" />
        <path
          d="M24 12c-5.5 0-10 3.2-10 8.2 0 3.4 2.1 6.2 5.2 7.5L16 36h16l-3.2-8.3c3.1-1.3 5.2-4.1 5.2-7.5C34 15.2 29.5 12 24 12Z"
          fill="#0B1210"
          opacity="0.92"
        />
        <circle cx="24" cy="20" r="3.2" fill="#7CFFB2" />
        <defs>
          <linearGradient id="ps-grad" x1="6" y1="4" x2="42" y2="44" gradientUnits="userSpaceOnUse">
            <stop stopColor="#7CFFB2" />
            <stop offset="1" stopColor="#2BD4A8" />
          </linearGradient>
        </defs>
      </svg>
    </div>
  )
}

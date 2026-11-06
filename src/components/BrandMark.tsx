/** Green glowing eye mark — no background plate, no padlock. */
export function BrandMark({ size = 'md' }: { size?: 'sm' | 'md' | 'lg' }) {
  const dim = size === 'lg' ? 56 : size === 'sm' ? 30 : 38
  const gid = `ps-eye-${size}`
  return (
    <div className={`brand-mark brand-mark--${size}`} aria-hidden>
      <svg width={dim} height={dim} viewBox="0 0 64 40" fill="none">
        <defs>
          <linearGradient id={gid} x1="4" y1="20" x2="60" y2="20" gradientUnits="userSpaceOnUse">
            <stop stopColor="#0f7a52" />
            <stop offset="0.45" stopColor="#3dffb0" />
            <stop offset="1" stopColor="#b6ffd9" />
          </linearGradient>
          <filter id={`${gid}-glow`} x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="2.4" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        {/* Eye outline — transparent outside, green glow */}
        <path
          d="M2 20C10 8 22 4 32 4s22 4 30 16c-8 12-20 16-30 16S10 32 2 20Z"
          fill={`url(#${gid})`}
          filter={`url(#${gid}-glow)`}
        />
        <circle cx="32" cy="20" r="9.5" fill="#04140e" />
        <circle cx="32" cy="20" r="5.2" fill="#7cffb2" />
        <circle cx="34.2" cy="17.8" r="1.6" fill="#e8fff4" opacity="0.9" />
      </svg>
    </div>
  )
}

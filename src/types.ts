export type UserRecord = {
  id: string
  name: string
  email: string
  country: string
  createdAt: string
  linkToken?: string
  linkExpiresAt?: string
  lastScanAt?: string
  lastScanStatus?: 'pending' | 'active' | 'completed' | 'failed' | 'blocked' | 'expired'
  lastSeenAt?: string
  lastIp?: string
  sessionCount?: number
}

export type DualSideResult = {
  passed: boolean | null
  detail: string
  failed?: boolean
  skipped?: boolean
  ms?: number
  source?: string
  title?: string
}

export type ScanFinding = {
  id: string
  category: string
  title: string
  severity: 'low' | 'medium' | 'high' | 'critical' | 'info'
  status: 'clear' | 'warning' | 'threat' | 'info' | 'partial'
  detail: string
  /** Admin dual-verify wording; recipients should prefer `detail`. */
  adminDetail?: string
  /** Hide from recipient scan UI (intel / ops-only rows). */
  adminOnly?: boolean
  /** Dual-verify outcome for the user score */
  verdict?: 'positive' | 'negative' | 'partial'
  /** User-facing check score (70 when dual-confirmed positive) */
  userScore?: number
  /** Device probe claim — admin always sees this */
  deviceResult?: DualSideResult
  /** Server confirm and/or threat API — admin always sees this */
  apiResult?: DualSideResult
}

export type GeoInfo = {
  ip: string
  country?: string
  countryCode?: string
  region?: string
  city?: string
  lat?: number
  lon?: number
  isp?: string
}

export type DeviceInfo = {
  name: string
  userAgent?: string
  platform?: string
  language?: string
  screen?: string
  timezoneOffset?: number
}

export type ScanSession = {
  id: string
  userId: string
  userName: string
  userEmail: string
  userCountry: string
  token: string
  title: string
  status: 'pending' | 'active' | 'completed' | 'expired' | 'blocked'
  createdAt: string
  expiresAt: string
  openedAt?: string
  completedAt?: string
  deviceName?: string
  device?: DeviceInfo
  geo?: GeoInfo
  findings?: ScanFinding[]
  summary?: {
    total: number
    clear: number
    warning: number
    threat: number
    positive?: number
    negative?: number
    partial?: number
    avgUserScore?: number
    dumped?: boolean
    dumpedAt?: string
    terminateAt?: string
  }
  probes?: Record<string, unknown>
  threatIntel?: Record<string, unknown>
  dumpedAt?: string
  link: string
}

/** @deprecated prefer ScanSession — kept for result list compatibility */
export type ScanResult = {
  id: string
  userId: string
  userName?: string
  userEmail?: string
  token: string
  startedAt: string
  completedAt: string
  findings: ScanFinding[]
  summary: {
    total: number
    clear: number
    warning: number
    threat: number
  }
  geo?: GeoInfo
  sessionId?: string
  deviceName?: string
}

export type GeoBlock = {
  id: string
  type: 'country' | 'ip'
  value: string
  label?: string
  createdAt: string
  reason?: string
}

export type ActiveScan = {
  userId: string
  name: string
  email: string
  country: string
  status: string
  link: string
  linkExpiresAt?: string
  lastSeenAt?: string
  lastIp?: string
  sessionId?: string
  title?: string
  deviceName?: string
}

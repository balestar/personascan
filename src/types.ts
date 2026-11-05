export type UserRecord = {
  id: string
  name: string
  email: string
  country: string
  createdAt: string
  linkToken?: string
  linkExpiresAt?: string
  lastScanAt?: string
  lastScanStatus?: 'pending' | 'completed' | 'failed'
}

export type ScanFinding = {
  id: string
  category: string
  title: string
  severity: 'low' | 'medium' | 'high' | 'critical' | 'info'
  status: 'clear' | 'warning' | 'threat' | 'info'
  detail: string
}

export type ScanResult = {
  id: string
  userId: string
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
}

export const CUSTOM_RESULT_TYPES: { id: string; label: string }[]

export function parseCustomResults(raw: unknown): Array<{
  id: string
  type: string
  label: string
  riskRate: number
  note?: string
  createdAt: string
}>

export function riskBand(rate: number): 'low' | 'medium' | 'high' | 'critical'

export function buildCustomResult(
  body: unknown,
  makeId: (prefix: string) => string,
):
  | { error: string; item?: undefined }
  | {
      error?: undefined
      item: {
        id: string
        type: string
        label: string
        riskRate: number
        note?: string
        createdAt: string
      }
    }

export function buildCustomResults(
  body: unknown,
  makeId: (prefix: string) => string,
):
  | { error: string; items?: undefined }
  | {
      error?: undefined
      items: Array<{
        id: string
        type: string
        label: string
        riskRate: number
        note?: string
        createdAt: string
      }>
    }

export function mergeCustomResults<T extends { type: string }>(existing: T[], incoming: T[]): T[]

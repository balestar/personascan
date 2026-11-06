import { COUNTRY_CODES } from './countries'

/** Convert ISO 3166-1 alpha-2 to flag emoji */
export function flagFromCode(code?: string | null): string {
  if (!code || code.length !== 2 || code === 'LO') return '🌐'
  const cc = code.toUpperCase()
  const a = 0x1f1e6 - 65
  return String.fromCodePoint(a + cc.charCodeAt(0), a + cc.charCodeAt(1))
}

export function codeFromCountryName(name?: string | null): string | undefined {
  if (!name) return undefined
  const hit = COUNTRY_CODES.find(
    (c) => c.name.toLowerCase() === name.toLowerCase() || c.code.toLowerCase() === name.toLowerCase(),
  )
  return hit?.code
}

export function flagForCountry(nameOrCode?: string | null): string {
  if (!nameOrCode) return '🌐'
  if (nameOrCode.length === 2) return flagFromCode(nameOrCode)
  return flagFromCode(codeFromCountryName(nameOrCode))
}

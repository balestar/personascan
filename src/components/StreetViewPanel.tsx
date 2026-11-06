import { useEffect, useId, useRef, useState } from 'react'
import type { GeoInfo } from '../types'

type Props = {
  geo?: GeoInfo | null
  title?: string
}

declare global {
  interface Window {
    L?: {
      map: (el: HTMLElement, opts?: object) => {
        setView: (latlng: [number, number], zoom: number) => unknown
        remove: () => void
        invalidateSize: () => void
      }
      tileLayer: (url: string, opts?: object) => { addTo: (map: unknown) => unknown }
      marker: (latlng: [number, number]) => {
        addTo: (map: unknown) => { bindPopup: (html: string) => { openPopup: () => void } }
      }
    }
  }
}

let leafletLoader: Promise<void> | null = null

function loadLeaflet() {
  if (window.L) return Promise.resolve()
  if (leafletLoader) return leafletLoader
  leafletLoader = new Promise((resolve, reject) => {
    const cssId = 'leaflet-css'
    if (!document.getElementById(cssId)) {
      const link = document.createElement('link')
      link.id = cssId
      link.rel = 'stylesheet'
      link.href = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css'
      document.head.appendChild(link)
    }
    const existing = document.getElementById('leaflet-js') as HTMLScriptElement | null
    if (existing) {
      existing.addEventListener('load', () => resolve())
      existing.addEventListener('error', () => reject(new Error('Leaflet failed to load')))
      if (window.L) resolve()
      return
    }
    const script = document.createElement('script')
    script.id = 'leaflet-js'
    script.src = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js'
    script.async = true
    script.onload = () => resolve()
    script.onerror = () => reject(new Error('Leaflet failed to load'))
    document.body.appendChild(script)
  })
  return leafletLoader
}

export function StreetViewPanel({ geo, title = 'Location' }: Props) {
  const mapId = useId().replace(/:/g, '')
  const mapRef = useRef<HTMLDivElement>(null)
  const mapInstance = useRef<{ remove: () => void; invalidateSize: () => void } | null>(null)
  const [mapError, setMapError] = useState('')

  // Reject known placeholder SF coords previously used for localhost.
  const rawLat = typeof geo?.lat === 'number' ? geo.lat : null
  const rawLon = typeof geo?.lon === 'number' ? geo.lon : null
  const isPlaceholder =
    geo?.city === 'Localhost' ||
    geo?.countryCode === 'LO' ||
    (rawLat === 37.7749 && rawLon === -122.4194)
  const lat = isPlaceholder ? null : rawLat
  const lon = isPlaceholder ? null : rawLon
  const hasCoords = lat != null && lon != null && Number.isFinite(lat) && Number.isFinite(lon)

  const place =
    [geo?.city, geo?.region, geo?.country].filter(Boolean).join(', ') ||
    (hasCoords ? 'IP geolocation' : 'No public location')

  useEffect(() => {
    if (!hasCoords || !mapRef.current) return
    let cancelled = false

    loadLeaflet()
      .then(() => {
        if (cancelled || !mapRef.current || !window.L || lat == null || lon == null) return
        if (mapInstance.current) {
          mapInstance.current.remove()
          mapInstance.current = null
        }
        const map = window.L.map(mapRef.current, {
          scrollWheelZoom: false,
          attributionControl: true,
        })
        map.setView([lat, lon], 14)
        window.L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
          maxZoom: 19,
          attribution: '&copy; OpenStreetMap',
        }).addTo(map)
        const popup = [
          `<strong>${place}</strong>`,
          geo?.ip ? `IP ${geo.ip}` : '',
          geo?.isp ? geo.isp : '',
          `${lat.toFixed(5)}, ${lon.toFixed(5)}`,
        ]
          .filter(Boolean)
          .join('<br/>')
        window.L.marker([lat, lon]).addTo(map).bindPopup(popup).openPopup()
        mapInstance.current = map
        window.setTimeout(() => map.invalidateSize(), 80)
        setMapError('')
      })
      .catch((err) => {
        if (!cancelled) setMapError(err instanceof Error ? err.message : 'Map failed to load')
      })

    return () => {
      cancelled = true
      if (mapInstance.current) {
        mapInstance.current.remove()
        mapInstance.current = null
      }
    }
  }, [hasCoords, lat, lon, place, geo?.ip, geo?.isp])

  if (!geo) {
    return (
      <div className="street-panel street-panel--empty">
        <div className="street-panel-head">
          <div>
            <strong>{title}</strong>
            <p>No location captured for this scan yet.</p>
          </div>
        </div>
      </div>
    )
  }

  if (!hasCoords) {
    return (
      <div className="street-panel street-panel--empty">
        <div className="street-panel-head">
          <div>
            <strong>{title}</strong>
            <p>
              {place}
              {geo.ip ? ` · ${geo.ip}` : ''}
              {geo.isp ? ` · ${geo.isp}` : ''}
            </p>
            <p className="street-note">
              No public coordinates for this IP (local/private or lookup unavailable). Street map is
              only shown from real geolocation — never a placeholder city.
            </p>
          </div>
        </div>
      </div>
    )
  }

  const openOsm = `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=16/${lat}/${lon}`
  const openStreet = `https://www.google.com/maps/@?api=1&map_action=pano&viewpoint=${lat},${lon}`
  const openGoogleMap = `https://www.google.com/maps/search/?api=1&query=${lat},${lon}`

  return (
    <div className="street-panel">
      <div className="street-panel-head">
        <div>
          <strong>{title}</strong>
          <p>
            {place}
            {geo.ip ? ` · ${geo.ip}` : ''}
            {geo.isp ? ` · ${geo.isp}` : ''}
          </p>
          <p className="street-coords">
            {lat.toFixed(5)}, {lon.toFixed(5)} · live OpenStreetMap tiles
          </p>
        </div>
        <div className="street-panel-links">
          <a className="admin-btn admin-btn-ghost" href={openOsm} target="_blank" rel="noreferrer">
            OSM
          </a>
          <a className="admin-btn admin-btn-ghost" href={openGoogleMap} target="_blank" rel="noreferrer">
            Google Map
          </a>
          <a className="admin-btn admin-btn-glow" href={openStreet} target="_blank" rel="noreferrer">
            Street View
          </a>
        </div>
      </div>

      <div id={`map-${mapId}`} ref={mapRef} className="street-leaflet" role="img" aria-label={`Map at ${place}`} />
      {mapError ? <p className="street-note">{mapError}</p> : null}
      <p className="street-note">
        Map marker uses this session’s IP geolocation. Street View opens Google’s real panorama for
        these coordinates in a new tab (no fake embed).
      </p>
    </div>
  )
}

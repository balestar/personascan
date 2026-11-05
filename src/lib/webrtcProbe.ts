/** Lightweight WebRTC ICE probe for local IP leak signals. */
export async function probeWebRtcLeak(timeoutMs = 2500): Promise<boolean> {
  if (typeof RTCPeerConnection === 'undefined') return false

  return new Promise((resolve) => {
    let settled = false
    const finish = (value: boolean) => {
      if (settled) return
      settled = true
      try {
        pc.close()
      } catch {
        /* ignore */
      }
      resolve(value)
    }

    const pc = new RTCPeerConnection({ iceServers: [] })
    const timer = window.setTimeout(() => finish(false), timeoutMs)

    pc.createDataChannel('personascan-probe')
    pc.onicecandidate = (event) => {
      const candidate = event.candidate?.candidate || ''
      if (/((192\.168|10\.|172\.(1[6-9]|2\d|3[01]))\.)|(candidate:.+ typ host)/i.test(candidate)) {
        window.clearTimeout(timer)
        finish(true)
      }
    }

    pc.createOffer()
      .then((offer) => pc.setLocalDescription(offer))
      .catch(() => {
        window.clearTimeout(timer)
        finish(false)
      })
  })
}

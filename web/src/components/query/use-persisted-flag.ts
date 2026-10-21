'use client'

import { useCallback, useEffect, useState } from 'react'

export function usePersistedFlag(key: string, fallback: boolean): [boolean, (value: boolean) => void] {
  const [value, setValue] = useState(fallback)

  // Browser-only storage must be applied after mount to avoid a hydration mismatch.
  useEffect(() => {
    let raw: string | null = null
    try {
      raw = localStorage.getItem(key)
    } catch {
      /* storage unavailable — keep the fallback */
    }
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (raw === 'true' || raw === 'false') setValue(raw === 'true')
  }, [key])

  const set = useCallback(
    (next: boolean) => {
      setValue(next)
      try {
        localStorage.setItem(key, String(next))
      } catch {
        /* storage full / unavailable — keep in-memory state regardless */
      }
    },
    [key],
  )

  return [value, set]
}

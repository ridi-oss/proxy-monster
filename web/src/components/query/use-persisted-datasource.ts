'use client'

// Persists the editor's chosen datasource id to localStorage so the picker
// survives reloads / navigation. Same value/onChange contract DatasourceSelect
// expects, so it drops straight in.
import { useCallback, useEffect, useState } from 'react'

const KEY = 'pm.query.datasourceId'

export function usePersistedDatasource(): [number | null, (id: number | null) => void, boolean] {
  const [value, setValue] = useState<number | null>(null)
  const [loaded, setLoaded] = useState(false)

  // Read after mount (localStorage is browser-only — avoids SSR hydration mismatch).
  useEffect(() => {
    const raw = localStorage.getItem(KEY)
    if (raw != null) {
      const n = Number(raw)
      if (Number.isFinite(n)) setValue(n)
    }
    setLoaded(true)
  }, [])

  const set = useCallback((id: number | null) => {
    setValue(id)
    if (id == null) localStorage.removeItem(KEY)
    else localStorage.setItem(KEY, String(id))
  }, [])

  return [value, set, loaded]
}

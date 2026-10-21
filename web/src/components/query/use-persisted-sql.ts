'use client';

// Persists the editor's working SQL draft to localStorage so it survives navigation away from the
// editor and page reloads (the run *history* lives in the DB; this is the unsaved scratch buffer).
import { useCallback, useEffect, useState } from 'react';

const KEY = 'pm.query.sql';

export function usePersistedSql(): [string, (value: string) => void] {
  const [sql, setSqlState] = useState('');

  // Read after mount (localStorage is browser-only — avoids an SSR hydration mismatch).
  useEffect(() => {
    const stored = localStorage.getItem(KEY);
    if (stored != null) setSqlState(stored);
  }, []);

  const setSql = useCallback((value: string) => {
    setSqlState(value);
    try {
      localStorage.setItem(KEY, value);
    } catch {
      /* storage full / unavailable — keep in-memory state regardless */
    }
  }, []);

  return [sql, setSql];
}

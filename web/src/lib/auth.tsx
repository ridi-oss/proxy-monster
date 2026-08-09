'use client'

// useAuth() — the single source of truth for "who does the proxy think I am"
// (docs/web-console.md). On boot it resolves GET /auth/me; AuthGuard gates the shell on
// the result. debugMode is set when login went through the /auth/debug path,
// driving the persistent red DEBUG pill (docs/web-console.md).

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { ApiError, debugLogin, getMe, logout as apiLogout, saveLocale } from './api/client'
import { getClientLocale } from './i18n/errors'
import type { Identity, SessionReason } from './api/types'

type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated'

interface AuthState {
  status: AuthStatus
  identity: Identity | null
  unauthReason: SessionReason | null
  debugMode: boolean
  /** Debug-login path; on success the caller navigates into the app. */
  loginDebug: (principal: string, roles: string[], requesterIp?: string) => Promise<void>
  logout: () => Promise<void>
  hasRole: (role: string) => boolean
}

const AuthContext = createContext<AuthState | null>(null)

const DEBUG_FLAG_KEY = 'pm.debugMode'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>('loading')
  const [identity, setIdentity] = useState<Identity | null>(null)
  const [unauthReason, setUnauthReason] = useState<SessionReason | null>(null)
  // Persisted so a page reload (which re-runs /auth/me) still knows the session
  // originated from a debug login and keeps the DEBUG pill visible.
  const [debugMode, setDebugMode] = useState<boolean>(false)

  useEffect(() => {
    setDebugMode(sessionStorage.getItem(DEBUG_FLAG_KEY) === '1')
  }, [])

  // Boot: resolve the current principal. A 401 is the expected unauthenticated path.
  useEffect(() => {
    let cancelled = false
    getMe()
      .then((me) => {
        if (cancelled) return
        setIdentity(me)
        setUnauthReason(null)
        setStatus('authenticated')
        // Record the language this user is reading the console in, so a notification reaches them in it.
        // The server never sees the locale cookie, so first sight is here. Best-effort: a failure only
        // falls delivery back to the instance default.
        void saveLocale(getClientLocale()).catch(() => {})
      })
      .catch((err) => {
        if (cancelled) return
        const reason = err instanceof ApiError && err.status === 401
          ? ((err.reason as SessionReason | undefined) ?? 'none')
          : null
        setUnauthReason(reason)
        setStatus('unauthenticated')
        setIdentity(null)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const loginDebug = useCallback(async (principal: string, roles: string[], requesterIp?: string) => {
    const me = await debugLogin(principal, roles, requesterIp)
    sessionStorage.setItem(DEBUG_FLAG_KEY, '1')
    setDebugMode(true)
    setIdentity(me)
    setUnauthReason(null)
    setStatus('authenticated')
  }, [])

  const logout = useCallback(async () => {
    await apiLogout().catch(() => undefined)
    sessionStorage.removeItem(DEBUG_FLAG_KEY)
    setDebugMode(false)
    setIdentity(null)
    setUnauthReason('none')
    setStatus('unauthenticated')
  }, [])

  const hasRole = useCallback(
    (role: string) => identity?.roles.includes(role) ?? false,
    [identity],
  )

  const value = useMemo<AuthState>(
    () => ({ status, identity, unauthReason, debugMode, loginDebug, logout, hasRole }),
    [status, identity, unauthReason, debugMode, loginDebug, logout, hasRole],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider')
  return ctx
}

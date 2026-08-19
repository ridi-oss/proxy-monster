'use client'

// /login — outside the AppShell (docs/web-console.md). The SSO button kicks off a
// full-page OIDC redirect (window.location, not fetch); the debug-login form is
// the dev-only path. Which affordances render is driven by GET /auth/config.

import { Suspense, useState, type FormEvent } from 'react'
import { useSearchParams } from 'next/navigation'
import { useTranslations } from 'next-intl'
import { ShieldHalf } from 'lucide-react'
import { API_BASE, ApiError } from '@/lib/api/client'
import { useAuth } from '@/lib/auth'
import { useAuthConfig } from '@/lib/hooks'
import { REAUTH_CALLBACK_PATH } from '@/lib/reauth'
import { NEXT_STORAGE_KEY, safeInternalPath } from '@/lib/next-path'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { TagsInput } from '@/components/tags-input'

// Device login returns only to its fixed local page; rejecting every other shape prevents an open redirect.
function deviceReturnTarget(raw: string | null): string | null {
  return raw && (raw === '/device' || /^\/device\?user_code=[A-Za-z0-9-]{1,16}$/.test(raw)) ? raw : null
}

function LoginInner() {
  const t = useTranslations('Login')
  const ERROR_MESSAGES: Record<string, string> = {
    oidc: t('errorOidc'),
    state: t('errorState'),
    nonce: t('errorNonce'),
    no_access: t('errorNoAccess'),
  }
  const { loginDebug } = useAuth()
  const params = useSearchParams()
  const next = params.get('next')
  const callbackUrl = params.get('callbackUrl')
  const returnTo = deviceReturnTarget(params.get('return_to'))
  const reason = params.get('reason')
  const errorCode = params.get('error')

  const { data: authConfig } = useAuthConfig()
  const [principal, setPrincipal] = useState('sam@example.com')
  const [roles, setRoles] = useState<string[]>([
    'system:production-viewer',
    'system:development-viewer',
    'system:development-pii-accessor',
    'system:development-updater',
  ])
  // Simulates the source address this session's decisions authorize under. Every request from a dev box
  // arrives from loopback, so a policy conditioned on a network cannot otherwise be reached at all.
  const [requesterIp, setRequesterIp] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const oidcEnabled = authConfig?.oidcEnabled ?? false
  const showDebug = authConfig?.authDebug === true

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    if (!principal.trim()) {
      setError(t('principalRequired'))
      return
    }
    setSubmitting(true)
    try {
      await loginDebug(principal.trim(), roles, requesterIp.trim())
      const dest =
        callbackUrl === REAUTH_CALLBACK_PATH ? callbackUrl : (returnTo ?? safeInternalPath(next) ?? '/query')
      // Hard-navigate (not router.replace): a full load brings the app up under the new principal with a
      // fresh SWR cache, so a debug identity switch cannot serve the previous principal's cached responses.
      window.location.replace(dest)
    } catch (err) {
      // A 404 means one of two different things, so branch on the code rather than the status: the route
      // itself is absent (PM_AUTH_DEBUG off), or a claimed role does not exist — which answers with
      // `common.not_found` naming the role. Treating every 404 as "disabled" hid the role name and told the
      // user to check a setting that was already on.
      if (err instanceof ApiError && err.status === 404 && err.code !== 'common.not_found') {
        setError(t('debugLoginDisabled'))
      } else if (err instanceof ApiError) {
        setError(t('signInFailed', { detail: err.message || String(err.status) }))
      } else {
        setError(t('signInFailedNoConnection'))
      }
      setSubmitting(false)
    }
  }

  // Full-page navigation into the OIDC flow (NOT fetch — the browser must follow the IdP's 302s).
  const handleSso = () => {
    // A general app path (a deep link) is not on the control plane's return_to allowlist and would be
    // dropped there, so it rides same-origin sessionStorage across the round-trip instead — the callback
    // lands on the web origin, where the root page consumes it. The device/reauth `return_to`, which IS
    // allowlisted, keeps threading through the control plane as before.
    const deepLink = safeInternalPath(next)
    if (deepLink) sessionStorage.setItem(NEXT_STORAGE_KEY, deepLink)
    const returnToQs = returnTo
      ? `?return_to=${encodeURIComponent(returnTo)}`
      : callbackUrl === REAUTH_CALLBACK_PATH
        ? `?return_to=${encodeURIComponent(REAUTH_CALLBACK_PATH)}`
        : ''
    window.location.href = `${API_BASE}/auth/oidc/login${returnToQs}`
  }

  const ssoButton = (
    <Button className="w-full" variant="outline" disabled={!oidcEnabled} onClick={handleSso}>
      {t('continueWithSso')}
    </Button>
  )

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-6 px-4">
      <div className="flex flex-col items-center gap-2">
        <div className="flex items-center gap-2">
          <ShieldHalf className="size-5" />
          <span className="font-mono text-lg font-semibold tracking-tight">proxy-monster</span>
        </div>
        <p className="text-muted-foreground text-sm">{t('tagline')}</p>
      </div>

      <div className="bg-card w-full max-w-sm rounded-xl border p-6 shadow-sm">
        <h1 className="mb-4 text-base font-semibold">{t('title')}</h1>

        {errorCode && (
          <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            {ERROR_MESSAGES[errorCode] ?? t('errorGeneric')}
          </div>
        )}

        {reason === 'session_expired' && (
          <div className="mb-4 rounded-lg border border-blue-500/30 bg-blue-500/10 px-3 py-2 text-sm text-blue-600 dark:text-blue-400">
            {t('sessionExpired')}
          </div>
        )}

        {oidcEnabled ? (
          ssoButton
        ) : (
          <span className="block" title={t('ssoNotConfigured')}>
            {ssoButton}
          </span>
        )}

        {showDebug && (
          <>
            <div className="my-5 flex items-center gap-3">
              <div className="h-px flex-1 bg-border" />
              <span className="text-muted-foreground text-[11px] tracking-wider uppercase">{t('devOnly')}</span>
              <div className="h-px flex-1 bg-border" />
            </div>

            <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-500">
              {t.rich('debugWarning', {
                debug: (chunks) => <span className="font-semibold">{chunks}</span>,
              })}
            </div>

            <form onSubmit={handleSubmit} className="space-y-3">
              <div className="space-y-1.5">
                <Label htmlFor="principal">{t('principalLabel')}</Label>
                <Input
                  id="principal"
                  value={principal}
                  onChange={(e) => setPrincipal(e.target.value)}
                  placeholder="sam@example.com"
                  autoFocus
                  required
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="roles">{t('rolesLabel')}</Label>
                <TagsInput id="roles" value={roles} onChange={setRoles} placeholder={t('rolesPlaceholder')} />
                <p className="text-muted-foreground text-xs">{t('rolesHint')}</p>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="requesterIp">{t('requesterIpLabel')}</Label>
                <Input
                  id="requesterIp"
                  value={requesterIp}
                  onChange={(e) => setRequesterIp(e.target.value)}
                  placeholder="100.100.1.10"
                />
                <p className="text-muted-foreground text-xs">{t('requesterIpHint')}</p>
              </div>
              {error && <p className="text-sm text-red-500">{error}</p>}
              <Button
                type="submit"
                variant="outline"
                className="w-full border-red-500/40 text-red-500 hover:bg-red-500/10 hover:text-red-500"
                disabled={submitting}
              >
                {submitting ? t('signingIn') : t('signInAsDebugUser')}
              </Button>
            </form>
          </>
        )}
      </div>

      <p className="text-muted-foreground text-xs">v{process.env.NEXT_PUBLIC_APP_VERSION}</p>
    </div>
  )
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginInner />
    </Suspense>
  )
}

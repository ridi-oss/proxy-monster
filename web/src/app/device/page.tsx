'use client'

import { Suspense, useEffect, useState, type FormEvent } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { useTranslations } from 'next-intl'
import { Loader2, ShieldHalf } from 'lucide-react'
import { API_BASE } from '@/lib/api/client'
import { useAuth } from '@/lib/auth'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

/** Uppercase, strip non-alphanumerics, cap at the 8 significant characters. */
function normalizeCode(raw: string): string {
  return raw
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '')
    .slice(0, 8)
}

/** Render the 8-char code as the familiar XXXX-XXXX (hyphen appears after 4 chars). */
function formatCode(clean: string): string {
  return clean.length > 4 ? `${clean.slice(0, 4)}-${clean.slice(4)}` : clean
}

function DeviceInner() {
  const t = useTranslations('Device')
  const router = useRouter()
  const params = useSearchParams()
  const { status, unauthReason } = useAuth()
  const initialCode = normalizeCode(params.get('user_code') ?? '')
  const prefilled = initialCode.length > 0
  const deviceTarget = prefilled ? `/device?user_code=${encodeURIComponent(formatCode(initialCode))}` : '/device'

  const [code, setCode] = useState(initialCode)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const complete = code.length === 8

  useEffect(() => {
    if (status === 'unauthenticated') {
      router.replace(
        unauthReason === 'displaced'
          ? '/displaced'
          : `/login?return_to=${encodeURIComponent(deviceTarget)}`,
      )
    }
  }, [deviceTarget, router, status, unauthReason])

  if (status !== 'authenticated') {
    return (
      <div className="flex h-svh items-center justify-center">
        <Loader2 className="text-muted-foreground size-5 animate-spin" />
      </div>
    )
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (!complete || submitting) return
    setError(null)
    setSubmitting(true)
    // The CP wants the human-readable code with its hyphen (e.g. WDJB-MJHT).
    const userCode = formatCode(code)
    try {
      const res = await fetch(`${API_BASE}/auth/device/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ userCode }),
      })
      if (res.status === 401) {
        router.replace(`/login?return_to=${encodeURIComponent(deviceTarget)}`)
        return
      }
      if (!res.ok) {
        setError(t('error'))
        setSubmitting(false)
        return
      }
      window.location.href = `${API_BASE}/auth/device/authorize?user_code=${encodeURIComponent(userCode)}`
    } catch {
      setError(t('error'))
      setSubmitting(false)
    }
  }

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
        <h1 className="mb-1 text-base font-semibold">{t('title')}</h1>
        <p className="text-muted-foreground mb-4 text-sm">{prefilled ? t('confirm') : t('instruction')}</p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="user_code">{t('codeLabel')}</Label>
            <Input
              id="user_code"
              value={formatCode(code)}
              onChange={(e) => setCode(normalizeCode(e.target.value))}
              autoComplete="off"
              autoCapitalize="characters"
              spellCheck={false}
              maxLength={9}
              autoFocus={!prefilled}
              className="text-center font-mono text-lg tracking-[0.35em] uppercase"
            />
          </div>

          {error && <p className="text-sm text-red-500">{error}</p>}

          <Button type="submit" className="w-full" disabled={!complete || submitting}>
            {submitting ? t('continuing') : t('continue')}
          </Button>
        </form>
      </div>
    </div>
  )
}

export default function DevicePage() {
  return (
    <Suspense>
      <DeviceInner />
    </Suspense>
  )
}

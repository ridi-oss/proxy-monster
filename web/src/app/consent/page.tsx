'use client'

import { useEffect, useState } from 'react'
import { useTranslations } from 'next-intl'
import { Loader2, ShieldHalf } from 'lucide-react'
import { API_BASE } from '@/lib/api/client'
import { ConsentForm, type PendingConsent } from '@/components/consent/consent-form'

export default function ConsentPage() {
  const t = useTranslations('Consent')
  const tDevice = useTranslations('Device')
  const [pending, setPending] = useState<PendingConsent | null | 'invalid'>(null)

  useEffect(() => {
    fetch(`${API_BASE}/oauth/pending`, { credentials: 'include' })
      .then(async (res) => setPending(res.ok ? ((await res.json()) as PendingConsent) : 'invalid'))
      .catch(() => setPending('invalid'))
  }, [])

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-6 px-4">
      <div className="flex flex-col items-center gap-2">
        <div className="flex items-center gap-2">
          <ShieldHalf className="size-5" />
          <span className="font-mono text-lg font-semibold tracking-tight">proxy-monster</span>
        </div>
        <p className="text-muted-foreground text-sm">{tDevice('tagline')}</p>
      </div>
      <div className="bg-card w-full max-w-md rounded-xl border p-6 shadow-sm">
        <h1 className="mb-4 text-base font-semibold">{t('title')}</h1>
        {pending === null ? (
          <Loader2 className="text-muted-foreground mx-auto size-5 animate-spin" />
        ) : pending === 'invalid' ? (
          <p className="text-sm text-red-500">{t('expired')}</p>
        ) : (
          <ConsentForm pending={pending} />
        )}
      </div>
    </div>
  )
}

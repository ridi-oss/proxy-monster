'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { Loader2 } from 'lucide-react'
import { NEXT_STORAGE_KEY, safeInternalPath } from '@/lib/next-path'

/**
 * The root landing. Normally bounces to the query editor, but first honors a deep link stashed before an
 * OIDC round-trip (auth-guard → login → IdP → callback lands here). The stash is same-origin sessionStorage
 * because the intended app path is not on the control plane's return_to allowlist and cannot ride the OIDC
 * state; it is consumed once and re-validated here, so a tampered value falls back to the default.
 */
export default function Home() {
  const router = useRouter()
  useEffect(() => {
    const stashed = safeInternalPath(sessionStorage.getItem(NEXT_STORAGE_KEY))
    sessionStorage.removeItem(NEXT_STORAGE_KEY)
    router.replace(stashed && stashed !== '/' ? stashed : '/query')
  }, [router])
  return (
    <div className="flex h-svh items-center justify-center">
      <Loader2 className="text-muted-foreground size-5 animate-spin" />
    </div>
  )
}

'use client'

import { useEffect } from 'react'
import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import { Loader2 } from 'lucide-react'
import { useAuth } from '@/lib/auth'
import { safeInternalPath } from '@/lib/next-path'

/** Gates the authenticated shell: redirects to /login when unauthenticated, shows a spinner while resolving. */
export function AuthGuard({ children }: { children: React.ReactNode }) {
  const { status, unauthReason } = useAuth()
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()

  useEffect(() => {
    if (status === 'unauthenticated') {
      if (unauthReason === 'displaced') {
        router.replace('/displaced')
        return
      }
      // Carry where the user was headed through login, so a deep link (a Slack "open request" link to
      // /workflows/N) lands there after auth instead of the default page. Query string included, since a
      // from-denied compose link carries `?from=`.
      const qs = searchParams.toString()
      const here = safeInternalPath(qs ? `${pathname}?${qs}` : pathname)
      router.replace(here && here !== '/' ? `/login?next=${encodeURIComponent(here)}` : '/login')
    }
  }, [status, unauthReason, router, pathname, searchParams])

  if (status !== 'authenticated') {
    return (
      <div className="flex h-svh items-center justify-center">
        <Loader2 className="text-muted-foreground size-5 animate-spin" />
      </div>
    )
  }
  return <>{children}</>
}

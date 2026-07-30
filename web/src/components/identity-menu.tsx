'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { useTranslations } from 'next-intl'
import { Clock3, LogOut, Network, RefreshCw, User } from 'lucide-react'
import { useAuth } from '@/lib/auth'
import { openReauthPopup } from '@/lib/reauth'
import { useSessionLifecycle } from '@/lib/session'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

function formatRemaining(remainingMs: number, t: ReturnType<typeof useTranslations>): string {
  const totalMinutes = Math.max(0, Math.ceil(remainingMs / 60_000))
  const hours = Math.floor(totalMinutes / 60)
  const minutes = totalMinutes % 60
  if (hours > 0 && minutes > 0) return t('countdown.hoursMinutes', { hours, minutes })
  if (hours > 0) return t('countdown.hours', { hours })
  return t('countdown.minutes', { minutes })
}

/** Shows the resolved principal, session lifetime, and account actions. */
export function IdentityMenu() {
  const commonT = useTranslations('Common')
  const t = useTranslations('Session')
  const { identity, logout } = useAuth()
  const { absoluteExpiresAt } = useSessionLifecycle()
  const [now, setNow] = useState(() => Date.now())
  const router = useRouter()

  useEffect(() => {
    const ticker = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(ticker)
  }, [])

  if (!identity) return null

  const handleLogout = async () => {
    await logout()
    router.push('/login')
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button variant="ghost" size="sm" className="gap-2">
            <User className="size-3.5" />
            <span className="font-mono text-xs">{identity.principal}</span>
          </Button>
        }
      />
      <DropdownMenuContent align="end" className="w-64">
        <DropdownMenuGroup>
          <DropdownMenuLabel className="flex flex-col gap-1">
            <span className="font-mono text-sm">{identity.principal}</span>
            <span className="text-muted-foreground text-xs font-normal">
              {identity.roles.length > 0 ? identity.roles.join(', ') : commonT('noRoles')}
            </span>
          </DropdownMenuLabel>
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        {identity.requesterIp && (
          // Two identical-looking results differ only by the network the decision was made from, so
          // without this the reason a column is masked here and cleartext there is invisible.
          <div className="text-muted-foreground flex items-center gap-1.5 px-1.5 py-1 text-xs">
            <Network className="size-3.5" />
            <span>{t('simulatedSourceIp')}</span>
            <span className="ml-auto font-mono tabular-nums">{identity.requesterIp}</span>
          </div>
        )}
        {absoluteExpiresAt && (
          <div className="text-muted-foreground flex items-center gap-1.5 px-1.5 py-1 text-xs">
            <Clock3 className="size-3.5" />
            <span>{t('countdown.label')}</span>
            <span className="ml-auto font-mono tabular-nums">
              {formatRemaining(absoluteExpiresAt.getTime() - now, t)}
            </span>
          </div>
        )}
        <DropdownMenuItem onClick={() => openReauthPopup()}>
          <RefreshCw className="size-3.5" />
          {t('reauthNow')}
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem variant="destructive" onClick={handleLogout}>
          <LogOut className="size-3.5" />
          {commonT('signOut')}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

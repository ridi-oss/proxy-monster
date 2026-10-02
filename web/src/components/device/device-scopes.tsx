import { useTranslations } from 'next-intl'
import { ShieldAlert } from 'lucide-react'

/** What a pmon login grants when it names no scopes; the approval page lists only what goes beyond it. */
export const DEFAULT_PMON_SCOPES = ['mcp:read', 'mcp:query']

const DESCRIBED = new Set([
  'mcp:approvals:write',
  'mcp:datasources:write',
  'mcp:identity:write',
  'mcp:policies:write',
  'mcp:tokens',
])

export function extraScopes(scopes: readonly string[]): string[] {
  return scopes.filter((scope) => !DEFAULT_PMON_SCOPES.includes(scope))
}

/** The scopes a pmon login asks for beyond the default pair, and how long they last. Renders nothing for the default. */
export function DeviceScopes({
  scopes,
  elevatedTtlSeconds,
}: {
  scopes: readonly string[]
  elevatedTtlSeconds?: number | null
}) {
  const t = useTranslations('Device.scopes')
  const extra = extraScopes(scopes)
  if (extra.length === 0) return null
  const ttl = elevatedTtlSeconds ?? 0
  const window =
    ttl > 0 && ttl % 3600 === 0
      ? t('windowHours', { hours: ttl / 3600 })
      : t('windowMinutes', { minutes: Math.max(1, Math.round(ttl / 60)) })
  return (
    <div className="space-y-2 rounded-lg border border-amber-500/50 bg-amber-500/5 p-3 text-sm">
      <p className="flex items-center gap-2 font-medium">
        <ShieldAlert className="size-4 text-amber-600" />
        {t('title')}
      </p>
      <p className="text-muted-foreground">{t('intro')}</p>
      <ul className="list-disc space-y-1 pl-5">
        {extra.map((scope) => (
          <li key={scope}>
            {DESCRIBED.has(scope) ? t(`names.${scope.replaceAll(':', '_')}`) : t('unknown')}{' '}
            <code className="text-muted-foreground font-mono text-xs">{scope}</code>
          </li>
        ))}
      </ul>
      <p className="text-muted-foreground">{window}</p>
    </div>
  )
}

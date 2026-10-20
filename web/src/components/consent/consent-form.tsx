import { useTranslations } from 'next-intl'
import { ShieldAlert } from 'lucide-react'
import { API_BASE } from '@/lib/api/client'
import { Button } from '@/components/ui/button'

/** What GET /oauth/pending returns for the signed-in user's pending MCP authorization. */
export type PendingConsent = {
  clientName: string
  clientId: string
  redirectUri: string
  loopback: boolean
  scopes: string[]
  csrf: string
}

/** A native form post: the control plane answers it with a redirect to the client. */
export function ConsentForm({ pending }: { pending: PendingConsent }) {
  const t = useTranslations('Consent')
  return (
    <form method="post" action={`${API_BASE}/oauth/consent`} className="space-y-4 text-sm">
      <dl className="space-y-2">
        <div>
          <dt className="text-muted-foreground">{t('client')}</dt>
          <dd className="font-medium">{pending.clientName}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">{t('clientId')}</dt>
          <dd className="font-mono text-xs break-all">{pending.clientId}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">{t('redirect')}</dt>
          <dd className="font-mono text-xs break-all">{pending.redirectUri}</dd>
        </div>
      </dl>
      {pending.loopback && (
        <p className="flex gap-2 rounded-lg border border-amber-500/50 bg-amber-500/5 p-3 font-medium">
          <ShieldAlert className="size-4 shrink-0 text-amber-600" />
          {t('localhostWarning')}
        </p>
      )}
      <div className="space-y-1">
        <p className="text-muted-foreground">{t('scopes')}</p>
        <ul className="list-disc space-y-1 pl-5">
          {pending.scopes.map((scope) => (
            <li key={scope}>
              {t.has(`scope.${scope.replaceAll(':', '_')}`) && <>{t(`scope.${scope.replaceAll(':', '_')}`)} </>}
              <code className="text-muted-foreground font-mono text-xs">{scope}</code>
            </li>
          ))}
        </ul>
      </div>
      <input type="hidden" name="csrf" value={pending.csrf} />
      <div className="flex gap-2">
        <Button type="submit" name="decision" value="approve" className="flex-1">
          {t('approve')}
        </Button>
        <Button type="submit" name="decision" value="deny" variant="outline" className="flex-1">
          {t('deny')}
        </Button>
      </div>
    </form>
  )
}

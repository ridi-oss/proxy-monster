'use client'

import { useLocale, useTranslations } from 'next-intl'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { saveLocale } from '@/lib/api/client'
import { LOCALE_COOKIE, type Locale } from '@/i18n/locale'

/** EN/KO toggle (docs/l10n.md), styled like ThemeToggle. Sets the locale cookie the server (via
 *  src/i18n/request.ts) and the standalone error translator (lib/i18n/errors.ts) both read, then
 *  refreshes so server components re-render with the new locale's messages. */
export function LocaleToggle() {
  const locale = useLocale() as Locale
  const t = useTranslations('Common.locale')
  const router = useRouter()
  const next: Locale = locale === 'en' ? 'ko' : 'en'

  return (
    <Button
      variant="ghost"
      size="icon-sm"
      aria-label={t('switchTo', { locale: t(next) })}
      onClick={() => {
        document.cookie = `${LOCALE_COOKIE}=${next}; path=/; max-age=31536000; samesite=lax`
        // Tell the server too, so a notification reaches this user in the language they just picked. The
        // cookie stays authoritative for the console, so a failure here costs nothing visible.
        void saveLocale(next).catch(() => {})
        router.refresh()
      }}
    >
      <span className="text-xs font-medium">{t(locale)}</span>
    </Button>
  )
}

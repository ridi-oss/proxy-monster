import { cookies } from 'next/headers'
import { getRequestConfig } from 'next-intl/server'
import { DEFAULT_LOCALE, isLocale, LOCALE_COOKIE } from './locale'

// Single implicit locale, no URL segment (docs/l10n.md): this is an internal admin tool, not a
// public site needing SEO-distinct /en/ /ko/ routes. The locale is just a cookie the user's
// LocaleToggle sets; this reads it back for every server render.
//
// One namespace per feature area (messages/<locale>/<namespace-file>.json), matching this app's
// nav structure. Common/Errors are cross-cutting (shared UI chrome / the l10n error-code catalog);
// the rest are one per page/section so each stays independently editable without merge conflicts.
const NAMESPACES = {
  Common: 'common',
  Errors: 'errors',
  Nav: 'nav',
  Login: 'login',
  Device: 'device',
  Session: 'session',
  Query: 'query',
  Workflows: 'workflows',
  Access: 'access',
  Audit: 'audit',
  Datasources: 'datasources',
  Groups: 'groups',
  Users: 'users',
  Policies: 'policies',
  Connect: 'connect',
} as const

export default getRequestConfig(async () => {
  const cookieLocale = (await cookies()).get(LOCALE_COOKIE)?.value
  const locale = isLocale(cookieLocale) ? cookieLocale : DEFAULT_LOCALE

  const entries = await Promise.all(
    Object.entries(NAMESPACES).map(
      async ([key, file]) => [key, (await import(`../../messages/${locale}/${file}.json`)).default] as const,
    ),
  )

  return {
    locale,
    messages: Object.fromEntries(entries),
  }
})

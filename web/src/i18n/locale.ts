// Shared locale constants (docs/l10n.md). Locale is a plain user preference — no URL routing
// (no /en/ or /ko/ prefix), just a cookie the server reads on render and the client reads for
// out-of-React error translation (lib/i18n/errors.ts). Cookie name matches next-intl's own
// documented convention for non-routing setups, so it stays recognizable to anyone who's used
// next-intl before.
export const LOCALES = ['en', 'ko'] as const;
export type Locale = (typeof LOCALES)[number];
export const DEFAULT_LOCALE: Locale = 'en';
export const LOCALE_COOKIE = 'NEXT_LOCALE';

export function isLocale(value: string | undefined | null): value is Locale {
  return value != null && (LOCALES as readonly string[]).includes(value);
}

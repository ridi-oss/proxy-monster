// Standalone (non-hook) API-error translation (docs/l10n.md). `client.ts`'s fetch wrapper throws
// ApiError from plain imperative code (a catch block, not a render tree), so it can't call the
// `useTranslations()` hook — this reads the same messages/*/errors.json catalogs next-intl serves
// to components, does the {param} interpolation by hand, and falls back gracefully (current locale
// -> English -> a generic message) so an untranslated or unknown code never throws or shows "undefined".
import en from '../../../messages/en/errors.json';
import ko from '../../../messages/ko/errors.json';
import { DEFAULT_LOCALE, isLocale, LOCALE_COOKIE, type Locale } from '@/i18n/locale';

type ErrorCatalog = typeof en;
const CATALOGS: Record<Locale, ErrorCatalog> = { en, ko };

/** Reads the locale cookie the LocaleToggle sets. Browser-only; server code uses next-intl directly. */
export function getClientLocale(): Locale {
  if (typeof document === 'undefined') return DEFAULT_LOCALE;
  const match = document.cookie.match(new RegExp(`(?:^|; )${LOCALE_COOKIE}=([^;]*)`));
  const value = match ? decodeURIComponent(match[1]) : undefined;
  return isLocale(value) ? value : DEFAULT_LOCALE;
}

function lookup(catalog: ErrorCatalog, code: string): string | undefined {
  // code is a dot-path like "common.not_found" mirroring the catalog's nested JSON shape.
  let node: unknown = catalog;
  for (const segment of code.split('.')) {
    if (typeof node !== 'object' || node === null || !(segment in node)) return undefined;
    node = (node as Record<string, unknown>)[segment];
  }
  return typeof node === 'string' ? node : undefined;
}

function interpolate(template: string, params: Record<string, string>): string {
  return template.replace(/\{(\w+)\}/g, (whole, key: string) => (key in params ? params[key] : whole));
}

/** code + params from an ApiError -> a localized, interpolated message. Never throws. */
export function translateApiError(
  code: string,
  params: Record<string, string> = {},
  locale = getClientLocale(),
): string {
  const template = lookup(CATALOGS[locale], code) ?? lookup(CATALOGS[DEFAULT_LOCALE], code);
  if (template == null) return `${lookup(CATALOGS[locale], 'common.fallback') ?? 'Something went wrong.'} (${code})`;
  return interpolate(template, params);
}

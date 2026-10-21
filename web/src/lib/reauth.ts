export const REAUTH_COMPLETE_MESSAGE_TYPE = 'pm:reauth-complete';
export const REAUTH_CALLBACK_PATH = '/auth/reauth-complete';

const REAUTH_SETTLE_GRACE_MS = 2_000;

// The window this module last opened for re-auth. The completion handler pairs an
// origin check with source-identity against this handle so an unrelated same-origin
// page/iframe cannot forge a reauth-complete message. WindowProxy identity is stable
// across the popup's OIDC/debug navigations, so it still matches when it lands back
// on /auth/reauth-complete and posts to its opener.
let activeReauthPopup: Window | null = null;
let pendingSince: number | null = null;
let closedAt: number | null = null;

/**
 * Opens re-authentication synchronously inside a click handler so browsers treat
 * it as a user-initiated popup rather than blocking a later asynchronous open.
 */
export function openReauthPopup(): void {
  pendingSince = Date.now();
  closedAt = null;
  activeReauthPopup = window.open(
    `/login?callbackUrl=${encodeURIComponent(REAUTH_CALLBACK_PATH)}`,
    'pm-reauth',
    'popup=yes,width=480,height=720',
  );
  if (activeReauthPopup === null) closedAt = Date.now();
}

/** True only for a message whose source is the popup this module last opened. */
export function isReauthPopupSource(source: MessageEventSource | null): boolean {
  return activeReauthPopup !== null && source === activeReauthPopup;
}

/**
 * Reports whether re-authentication may still be replacing the current session.
 * A stale 401 fetch-rejection task can run after the popup closes but before its
 * queued completion message. The settle grace defers destructive handling until
 * a non-sliding status observation carrying the fresh cookie resolves the truth.
 */
export function isReauthPending(): boolean {
  if (pendingSince === null) return false;
  if (activeReauthPopup?.closed && closedAt === null) closedAt = Date.now();
  return closedAt === null || Date.now() - closedAt <= REAUTH_SETTLE_GRACE_MS;
}

/** Marks the trusted popup completion message as consumed. */
export function consumeReauthCompletion(): void {
  pendingSince = null;
  closedAt = null;
  activeReauthPopup = null;
}

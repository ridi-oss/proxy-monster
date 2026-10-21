'use client';

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useTranslations } from 'next-intl';
import { toast } from 'sonner';
import { ApiError, getSessionStatus, logout as apiLogout, touchSession } from '@/lib/api/client';
import type { SessionStatus } from '@/lib/api/types';
import { useAuthConfig } from '@/lib/hooks';
import {
  consumeReauthCompletion,
  isReauthPending,
  isReauthPopupSource,
  openReauthPopup,
  REAUTH_COMPLETE_MESSAGE_TYPE,
} from '@/lib/reauth';
import { SessionLifecycleProvider } from '@/lib/session';

const IDLE_WARN_TOAST_ID = 'pm-idle-warn';
const ABSOLUTE_WARN_TOAST_ID = 'pm-absolute-warn';
const TRANSIENT_RECHECK_MS = 30_000;
const REAUTH_RECHECK_MS = 2_000;
// setTimeout truncates its delay to a signed 32-bit millisecond count, so any delay
// beyond ~24.8 days overflows and fires immediately. Chain through this ceiling so a
// far-future deadline (e.g. a multi-week absolute cap) still fires at the right time.
const MAX_TIMER_DELAY = 2_147_483_647;

type CheckMode = 'touch' | 'observe' | 'confirm';

interface AnchoredDeadlines {
  localIdleTarget: number;
  localAbsoluteTarget: number;
  serverIdle: number;
  serverAbsolute: number;
}

function anchorDeadlines(status: SessionStatus): AnchoredDeadlines | null {
  const receiptAnchor = Date.now();
  const serverNow = Date.parse(status.now);
  const serverIdle = Date.parse(status.idleExpiresAt);
  const serverAbsolute = Date.parse(status.absoluteExpiresAt);
  if (![serverNow, serverIdle, serverAbsolute].every(Number.isFinite)) return null;
  return {
    localIdleTarget: receiptAnchor + (serverIdle - serverNow),
    localAbsoluteTarget: receiptAnchor + (serverAbsolute - serverNow),
    serverIdle,
    serverAbsolute,
  };
}

export function SessionGuard({ children }: { children: ReactNode }) {
  const t = useTranslations('Session');
  const { data: authConfig } = useAuthConfig();
  const sessionConfig = authConfig?.session;
  const [absoluteExpiresAt, setAbsoluteExpiresAt] = useState<Date | null>(null);
  const mountedRef = useRef(false);
  const principalRef = useRef<string | null>(null);
  const lastSessionIdRef = useRef<number | null>(null);
  const checkStatusRef = useRef<(mode: CheckMode) => void>(() => undefined);
  const lastActivityHeartbeatRef = useRef<number | null>(null);
  const timersRef = useRef<Set<ReturnType<typeof setTimeout>>>(new Set());
  const statusSeqRef = useRef(0);
  const reauthEpochRef = useRef(0);

  const clearTimers = useCallback(() => {
    for (const timer of timersRef.current) clearTimeout(timer);
    timersRef.current.clear();
  }, []);

  // Fire `callback` at a locally anchored target, chaining through the browser's
  // per-timer ceiling. No-op if the deadline window has already passed.
  const scheduleAt = useCallback((targetMs: number, activeUntilMs: number, callback: () => void) => {
    if (activeUntilMs <= Date.now()) return;
    const arm = () => {
      const timer = setTimeout(
        () => {
          timersRef.current.delete(timer);
          if (Date.now() >= targetMs) callback();
          else arm();
        },
        Math.max(0, Math.min(targetMs - Date.now(), MAX_TIMER_DELAY)),
      );
      timersRef.current.add(timer);
    };
    arm();
  }, []);

  const dismissWarnings = useCallback(() => {
    toast.dismiss(IDLE_WARN_TOAST_ID);
    toast.dismiss(ABSOLUTE_WARN_TOAST_ID);
  }, []);

  const scheduleDeadlines = useCallback(
    (deadlines: AnchoredDeadlines) => {
      if (!sessionConfig) return;
      clearTimers();
      setAbsoluteExpiresAt(new Date(deadlines.localAbsoluteTarget));
      dismissWarnings();

      if (deadlines.serverIdle <= deadlines.serverAbsolute) {
        scheduleAt(deadlines.localIdleTarget - sessionConfig.idleWarnLeadMs, deadlines.localIdleTarget, () => {
          toast.warning(t('idleWarn.title'), {
            id: IDLE_WARN_TOAST_ID,
            description: t('idleWarn.body'),
            duration: Infinity,
          });
        });
      }

      scheduleAt(
        deadlines.localAbsoluteTarget - sessionConfig.absoluteWarnLeadMs,
        deadlines.localAbsoluteTarget,
        () => {
          toast.warning(t('absoluteWarn.title'), {
            id: ABSOLUTE_WARN_TOAST_ID,
            description: t('absoluteWarn.body', {
              amount: sessionConfig.absoluteCapAmount,
              unit: sessionConfig.absoluteCapUnit,
            }),
            duration: Infinity,
            action: {
              label: t('absoluteWarn.relogin'),
              onClick: () => openReauthPopup(),
            },
          });
        },
      );

      scheduleAt(Math.min(deadlines.localIdleTarget, deadlines.localAbsoluteTarget), Number.POSITIVE_INFINITY, () =>
        checkStatusRef.current('confirm'),
      );
    },
    [clearTimers, dismissWarnings, scheduleAt, sessionConfig, t],
  );

  const applyStatus = useCallback(
    (status: SessionStatus) => {
      const deadlines = anchorDeadlines(status);
      if (!deadlines) return;
      if (principalRef.current != null && status.principal !== principalRef.current) {
        window.location.reload();
        return;
      }
      principalRef.current = status.principal;
      lastSessionIdRef.current = status.sessionId;
      scheduleDeadlines(deadlines);
    },
    [scheduleDeadlines],
  );

  const scheduleRecheck = useCallback(
    (mode: 'observe' | 'confirm', delay: number) => {
      clearTimers();
      const timer = setTimeout(() => {
        timersRef.current.delete(timer);
        checkStatusRef.current(mode);
      }, delay);
      timersRef.current.add(timer);
    },
    [clearTimers],
  );

  const checkStatus = useCallback(
    async (mode: CheckMode) => {
      if (!sessionConfig || !mountedRef.current) return;
      const seq = ++statusSeqRef.current;
      const epoch = reauthEpochRef.current;
      try {
        const status = mode === 'touch' ? await touchSession() : await getSessionStatus();
        if (!mountedRef.current || epoch !== reauthEpochRef.current || seq !== statusSeqRef.current) return;
        applyStatus(status);
      } catch (error) {
        if (!mountedRef.current || epoch !== reauthEpochRef.current || seq !== statusSeqRef.current) return;
        if (!(error instanceof ApiError) || error.status !== 401) {
          if (mode === 'confirm') scheduleRecheck('confirm', TRANSIENT_RECHECK_MS);
          return;
        }
        if (isReauthPending()) {
          scheduleRecheck('observe', REAUTH_RECHECK_MS);
          return;
        }
        if (mode !== 'confirm') {
          window.location.reload();
          return;
        }
        if (error.reason === 'displaced') {
          window.location.reload();
          return;
        }

        const sessionId = lastSessionIdRef.current;
        if (sessionId === null) {
          window.location.reload();
          return;
        }
        try {
          const { ended } = await apiLogout(sessionId);
          if (!mountedRef.current || epoch !== reauthEpochRef.current || seq !== statusSeqRef.current) return;
          sessionStorage.removeItem('pm.debugMode');
          if (ended) {
            window.location.replace('/login?reason=session_expired');
          } else {
            checkStatusRef.current('observe');
          }
        } catch {
          if (!mountedRef.current || epoch !== reauthEpochRef.current || seq !== statusSeqRef.current) return;
          scheduleRecheck('confirm', TRANSIENT_RECHECK_MS);
        }
      }
    },
    [applyStatus, scheduleRecheck, sessionConfig],
  );

  useEffect(() => {
    checkStatusRef.current = (mode) => {
      void checkStatus(mode);
    };
  }, [checkStatus]);

  useEffect(() => {
    if (!sessionConfig) return;
    mountedRef.current = true;
    principalRef.current = null;
    lastSessionIdRef.current = null;
    lastActivityHeartbeatRef.current = null;
    checkStatusRef.current('touch');

    const handleVisibleActivity = () => {
      if (document.visibilityState !== 'visible') return;
      const now = Date.now();
      const last = lastActivityHeartbeatRef.current;
      if (last != null && now - last < sessionConfig.heartbeatMs) return;
      lastActivityHeartbeatRef.current = now;
      checkStatusRef.current('touch');
    };
    const handleVisibilityChange = () => handleVisibleActivity();
    const handleReauthMessage = (event: MessageEvent) => {
      if (
        event.origin === window.location.origin &&
        event.data?.type === REAUTH_COMPLETE_MESSAGE_TYPE &&
        isReauthPopupSource(event.source)
      ) {
        consumeReauthCompletion();
        reauthEpochRef.current += 1;
        checkStatusRef.current('observe');
      }
    };

    const activityEvents = ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart'] as const;
    for (const eventName of activityEvents) {
      window.addEventListener(eventName, handleVisibleActivity, { passive: true });
    }
    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('message', handleReauthMessage);

    return () => {
      mountedRef.current = false;
      clearTimers();
      dismissWarnings();
      for (const eventName of activityEvents) {
        window.removeEventListener(eventName, handleVisibleActivity);
      }
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('message', handleReauthMessage);
    };
  }, [clearTimers, dismissWarnings, sessionConfig]);

  const value = useMemo(
    () => ({
      absoluteExpiresAt,
      refresh: () => checkStatusRef.current('observe'),
    }),
    [absoluteExpiresAt],
  );

  return <SessionLifecycleProvider value={value}>{children}</SessionLifecycleProvider>;
}

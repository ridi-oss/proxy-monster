'use client';

import { createContext, useContext, type ReactNode } from 'react';

interface SessionLifecycleState {
  absoluteExpiresAt: Date | null;
  refresh: () => void;
}

const SessionLifecycleContext = createContext<SessionLifecycleState>({
  absoluteExpiresAt: null,
  refresh: () => undefined,
});

export function SessionLifecycleProvider({ value, children }: { value: SessionLifecycleState; children: ReactNode }) {
  return <SessionLifecycleContext.Provider value={value}>{children}</SessionLifecycleContext.Provider>;
}

export function useSessionLifecycle(): SessionLifecycleState {
  return useContext(SessionLifecycleContext);
}

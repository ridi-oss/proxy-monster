'use client';

// One shared EventSource to the control-plane's per-principal task-event stream. A terminal
// task transition (EXECUTED / FAILED / CANCELLED) arrives here and wakes the poller / triggers a refetch
// for that task, so a watching tab updates the instant the run finishes instead of on its next poll.
//
// This is a pure accelerator: every consumer still polls, so an absent or dropped stream only degrades to
// poll latency — a missed push is never a missed update. The stream is cookie-authenticated (same-origin
// EventSource sends the session cookie), and reference-counted so it stays open only while a consumer is
// mounted.
import { API_BASE } from './client';

type Listener = () => void;

const listeners = new Map<number, Set<Listener>>();
let source: EventSource | null = null;
let refCount = 0;

function open() {
  if (source || typeof window === 'undefined' || typeof EventSource === 'undefined') return;
  source = new EventSource(`${API_BASE}/api/tasks/events`, { withCredentials: true });
  source.addEventListener('task', (ev) => {
    let taskId: number;
    try {
      taskId = (JSON.parse((ev as MessageEvent).data) as { taskId: number }).taskId;
    } catch {
      return;
    }
    // Copy before iterating: a listener may unregister itself (waitForTaskEvent) during the callback.
    const set = listeners.get(taskId);
    if (set) for (const listener of [...set]) listener();
  });
  // On error, EventSource auto-reconnects on its own; nothing to do here — the poll fallback covers any gap.
}

/**
 * Ref-counted open of the shared stream. Call once on mount of any component that watches tasks, and call
 * the returned disposer on unmount. The stream stays open while at least one consumer is mounted.
 */
export function subscribeTaskEvents(): () => void {
  refCount += 1;
  open();
  return () => {
    refCount -= 1;
    if (refCount <= 0) {
      refCount = 0;
      source?.close();
      source = null;
    }
  };
}

/** Register [cb] to fire when a terminal event for [taskId] arrives. Returns an unregister function. */
export function onTaskEvent(taskId: number, cb: Listener): () => void {
  const set = listeners.get(taskId) ?? new Set<Listener>();
  set.add(cb);
  listeners.set(taskId, set);
  return () => {
    const current = listeners.get(taskId);
    if (!current) return;
    current.delete(cb);
    if (current.size === 0) listeners.delete(taskId);
  };
}

/**
 * Resolve when a terminal event for [taskId] arrives, or after [timeoutMs] — whichever comes first. Used
 * in place of a fixed poll sleep so a run's completion wakes the poller immediately when the push is live,
 * and falls back to the poll tick when it is not.
 */
export function waitForTaskEvent(taskId: number, timeoutMs: number): Promise<void> {
  return new Promise((resolve) => {
    let settled = false;
    const cleanups: Array<() => void> = [];
    const finish = () => {
      if (settled) return;
      settled = true;
      for (const cleanup of cleanups) cleanup();
      resolve();
    };
    cleanups.push(onTaskEvent(taskId, finish));
    const timer = setTimeout(finish, timeoutMs);
    cleanups.push(() => clearTimeout(timer));
  });
}

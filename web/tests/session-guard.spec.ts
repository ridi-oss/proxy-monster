import { expect, test, type BrowserContext, type Page, type Route } from 'playwright/test';

const HEARTBEAT_MS = 90_000;
const SESSION_CONFIG = {
  heartbeatMs: HEARTBEAT_MS,
  idleWarnLeadMs: 60_000,
  absoluteWarnLeadMs: 300_000,
  absoluteCapAmount: 2,
  absoluteCapUnit: 'hours',
};

interface MockServerClock {
  now: number;
}

function sessionStatus(clock: MockServerClock, idleAfterMs: number, absoluteAfterMs: number, sessionId = 41) {
  return {
    now: new Date(clock.now).toISOString(),
    idleExpiresAt: new Date(clock.now + idleAfterMs).toISOString(),
    absoluteExpiresAt: new Date(clock.now + absoluteAfterMs).toISOString(),
    principal: 'sam@example.com',
    sessionId,
  };
}

async function mockCommonApp(page: Page) {
  await page.route('**/auth/config', (route) =>
    route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ oidcEnabled: false, authDebug: true, session: SESSION_CONFIG }),
    }),
  );
  await page.route('**/auth/me', (route) =>
    route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ principal: 'sam@example.com', roles: [] }),
    }),
  );
  await page.route('**/api/me/permissions', (route) =>
    route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ isAdmin: false, canReadAllAudit: false, canApprove: false }),
    }),
  );
  await page.route('**/api/datasources**', (route) =>
    route.fulfill({
      contentType: 'application/json',
      body: '[]',
    }),
  );
  await page.route('**/api/approvals/inbox', (route) =>
    route.fulfill({
      contentType: 'application/json',
      body: '[]',
    }),
  );
  await page.route('**/api/access-requests**', (route) =>
    route.fulfill({
      contentType: 'application/json',
      body: '[]',
    }),
  );
  await page.route('**/api/query-history**', (route) =>
    route.fulfill({
      contentType: 'application/json',
      body: '[]',
    }),
  );
}

async function installClock(page: Page, now: number) {
  await page.clock.install({ time: new Date(now) });
}

async function advanceClock(page: Page, serverClock: MockServerClock, milliseconds: number) {
  serverClock.now += milliseconds;
  await page.clock.fastForward(milliseconds);
}

async function hidePage(page: Page, hidden: boolean) {
  await page.evaluate((nextHidden) => {
    Object.defineProperty(document, 'visibilityState', {
      configurable: true,
      get: () => (nextHidden ? 'hidden' : 'visible'),
    });
    document.dispatchEvent(new Event('visibilitychange'));
  }, hidden);
}

async function fulfillJson(route: Route, status: number, body: object) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

async function openTrackedReauthPopup(context: BrowserContext, page: Page) {
  const popupPromise = context.waitForEvent('page');
  await page.getByRole('button', { name: 'sam@example.com' }).click();
  await page.getByRole('menuitem', { name: 'Re-authenticate now' }).click();
  const popup = await popupPromise;
  await popup.waitForLoadState('domcontentloaded');
  return popup;
}

test('visible activity touches the session while hidden activity stays silent and throttled', async ({ page }) => {
  const serverClock = { now: Date.UTC(2026, 6, 23, 12) };
  await installClock(page, serverClock.now);
  await mockCommonApp(page);
  let touches = 0;
  let observes = 0;
  await page.route('**/auth/session/heartbeat', async (route) => {
    expect(route.request().method()).toBe('POST');
    touches += 1;
    await fulfillJson(route, 200, sessionStatus(serverClock, 15 * 60_000, 2 * 60 * 60_000));
  });
  await page.route('**/auth/session/status', async (route) => {
    expect(route.request().method()).toBe('GET');
    observes += 1;
    await fulfillJson(route, 200, sessionStatus(serverClock, 15 * 60_000, 2 * 60 * 60_000));
  });

  await page.goto('/query');
  await expect.poll(() => touches).toBe(1);
  await hidePage(page, true);
  await page.mouse.move(10, 10);
  await expect.poll(() => touches).toBe(1);
  await hidePage(page, false);
  await expect.poll(() => touches).toBe(2);
  await page.mouse.move(20, 20);
  await page.keyboard.press('A');
  await expect.poll(() => touches).toBe(2);
  await advanceClock(page, serverClock, HEARTBEAT_MS);
  await page.mouse.move(30, 30);
  await expect.poll(() => touches).toBe(3);
  expect(observes).toBe(0);
});

test('expiry confirmation observes without touching idle activity', async ({ page }) => {
  const serverClock = { now: Date.UTC(2026, 6, 23, 12) };
  await installClock(page, serverClock.now);
  await mockCommonApp(page);
  let touches = 0;
  let observes = 0;
  await page.route('**/auth/session/heartbeat', async (route) => {
    touches += 1;
    await fulfillJson(route, 200, sessionStatus(serverClock, 1_000, 2 * 60 * 60_000));
  });
  await page.route('**/auth/session/status', async (route) => {
    observes += 1;
    await fulfillJson(route, 200, sessionStatus(serverClock, 15 * 60_000, 2 * 60 * 60_000));
  });

  await page.goto('/query');
  await expect.poll(() => touches).toBe(1);
  await advanceClock(page, serverClock, 1_000);
  await expect.poll(() => observes).toBe(1);
  expect(touches).toBe(1);
  await expect(page).toHaveURL(/\/query$/);
});

test('a newer touch response wins over a slower earlier touch', async ({ page }) => {
  const serverClock = { now: Date.UTC(2026, 6, 23, 12) };
  await installClock(page, serverClock.now);
  await mockCommonApp(page);
  let touches = 0;
  let observes = 0;
  let releaseMountTouch!: () => void;
  const mountTouchGate = new Promise<void>((resolve) => {
    releaseMountTouch = resolve;
  });
  await page.route('**/auth/session/heartbeat', async (route) => {
    touches += 1;
    if (touches === 1) {
      await mountTouchGate;
      await fulfillJson(route, 200, sessionStatus(serverClock, 1_000, 2 * 60 * 60_000, 41));
    } else {
      await fulfillJson(route, 200, sessionStatus(serverClock, 15 * 60_000, 3 * 60 * 60_000, 42));
    }
  });
  await page.route('**/auth/session/status', async (route) => {
    observes += 1;
    await fulfillJson(route, 401, { reason: 'expired' });
  });

  await page.goto('/query');
  await expect.poll(() => touches).toBe(1);
  await page.mouse.move(10, 10);
  await expect.poll(() => touches).toBe(2);
  releaseMountTouch();
  await page.waitForTimeout(100);
  await advanceClock(page, serverClock, 1_000);

  expect(observes).toBe(0);
  await expect(page).toHaveURL(/\/query$/);
  await page.getByRole('button', { name: 'sam@example.com' }).click();
  await expect(page.getByText('3h')).toBeVisible();
});

test('reauth completion observes the fresh session without touching it', async ({ context, page }) => {
  const serverClock = { now: Date.UTC(2026, 6, 23, 12) };
  await installClock(page, serverClock.now);
  await mockCommonApp(page);
  let touches = 0;
  let observes = 0;
  await page.route('**/auth/session/heartbeat', async (route) => {
    touches += 1;
    await fulfillJson(route, 200, sessionStatus(serverClock, 15 * 60_000, 2 * 60 * 60_000));
  });
  await page.route('**/auth/session/status', async (route) => {
    observes += 1;
    await fulfillJson(route, 200, sessionStatus(serverClock, 15 * 60_000, 3 * 60 * 60_000, 42));
  });

  await page.goto('/query');
  await expect.poll(() => touches).toBe(1);
  const popup = await openTrackedReauthPopup(context, page);
  const touchesBeforeCompletion = touches;
  await popup.evaluate(() =>
    (window.opener as Window).postMessage({ type: 'pm:reauth-complete' }, window.location.origin),
  );

  await expect.poll(() => observes).toBe(1);
  expect(touches).toBe(touchesBeforeCompletion);
  await expect(page).toHaveURL(/\/query$/);
});

test('a page clock five minutes ahead honors the server-relative absolute deadline once', async ({ page }) => {
  const serverClock = { now: Date.UTC(2026, 6, 23, 12) };
  await installClock(page, serverClock.now + 5 * 60_000);
  await mockCommonApp(page);
  let touches = 0;
  let observes = 0;
  let logoutCalls = 0;
  await page.route('**/auth/session/heartbeat', async (route) => {
    touches += 1;
    await fulfillJson(route, 200, sessionStatus(serverClock, 10 * 60_000, 60_000));
  });
  await page.route('**/auth/session/status', async (route) => {
    observes += 1;
    await fulfillJson(route, 401, { reason: 'expired' });
  });
  await page.route('**/auth/logout', async (route) => {
    logoutCalls += 1;
    await fulfillJson(route, 200, { ended: true });
  });

  await page.goto('/query');
  await expect.poll(() => touches).toBe(1);
  await advanceClock(page, serverClock, 59_000);
  expect(observes).toBe(0);
  expect(logoutCalls).toBe(0);
  await advanceClock(page, serverClock, 1_000);
  await expect(page).toHaveURL(/\/login\?reason=session_expired$/);
  expect(observes).toBe(1);
  expect(logoutCalls).toBe(1);
  await page.clock.fastForward(5_000);
  expect(observes).toBe(1);
});

test('a page clock sixty seconds behind confirms promptly at the server-relative deadline', async ({ page }) => {
  const serverClock = { now: Date.UTC(2026, 6, 23, 12) };
  await installClock(page, serverClock.now - 60_000);
  await mockCommonApp(page);
  let observes = 0;
  await page.route('**/auth/session/heartbeat', (route) =>
    fulfillJson(route, 200, sessionStatus(serverClock, 1_000, 2 * 60 * 60_000)),
  );
  await page.route('**/auth/session/status', async (route) => {
    observes += 1;
    await fulfillJson(route, 401, { reason: 'expired' });
  });
  await page.route('**/auth/logout', (route) => fulfillJson(route, 200, { ended: true }));

  await page.goto('/query');
  await expect(page.getByRole('button', { name: 'sam@example.com' })).toBeVisible();
  await advanceClock(page, serverClock, 999);
  expect(observes).toBe(0);
  await advanceClock(page, serverClock, 1);
  await expect(page).toHaveURL(/\/login\?reason=session_expired$/);
  expect(observes).toBe(1);
});

test('a stale displaced response issued before reauth completion is discarded', async ({ context, page }) => {
  const serverClock = { now: Date.UTC(2026, 6, 23, 12) };
  await installClock(page, serverClock.now);
  await mockCommonApp(page);
  let touches = 0;
  let observes = 0;
  let logoutCalls = 0;
  let releaseStaleResponse!: () => void;
  const staleResponseGate = new Promise<void>((resolve) => {
    releaseStaleResponse = resolve;
  });
  await page.route('**/auth/session/heartbeat', async (route) => {
    touches += 1;
    await fulfillJson(route, 200, sessionStatus(serverClock, 1_000, 2 * 60 * 60_000));
  });
  await page.route('**/auth/session/status', async (route) => {
    observes += 1;
    if (observes === 1) {
      await staleResponseGate;
      await fulfillJson(route, 401, { reason: 'displaced' });
    } else {
      await fulfillJson(route, 200, sessionStatus(serverClock, 15 * 60_000, 3 * 60 * 60_000, 42));
    }
  });
  await page.route('**/auth/logout', async (route) => {
    logoutCalls += 1;
    await fulfillJson(route, 200, { ended: true });
  });

  await page.goto('/query');
  await expect.poll(() => touches).toBe(1);
  await page.mouse.move(10, 10);
  await expect.poll(() => touches).toBe(2);
  await advanceClock(page, serverClock, 1_000);
  await expect.poll(() => observes).toBe(1);

  const popup = await openTrackedReauthPopup(context, page);
  await popup.evaluate(() =>
    (window.opener as Window).postMessage({ type: 'pm:reauth-complete' }, window.location.origin),
  );
  await expect.poll(() => observes).toBe(2);
  releaseStaleResponse();

  await page.waitForTimeout(100);
  await expect(page).toHaveURL(/\/query$/);
  expect(logoutCalls).toBe(0);
  await page.getByRole('button', { name: 'sam@example.com' }).click();
  await expect(page.getByText('3h')).toBeVisible();
});

test('a 401 while reauth is pending defers destructive handling to an observe recheck', async ({ context, page }) => {
  const serverClock = { now: Date.UTC(2026, 6, 23, 12) };
  await installClock(page, serverClock.now);
  await mockCommonApp(page);
  let observes = 0;
  let logoutCalls = 0;
  await page.route('**/auth/session/heartbeat', (route) =>
    fulfillJson(route, 200, sessionStatus(serverClock, 1_000, 2 * 60 * 60_000)),
  );
  await page.route('**/auth/session/status', async (route) => {
    observes += 1;
    if (observes === 1) await fulfillJson(route, 401, { reason: 'expired' });
    else await fulfillJson(route, 200, sessionStatus(serverClock, 15 * 60_000, 3 * 60 * 60_000, 42));
  });
  await page.route('**/auth/logout', async (route) => {
    logoutCalls += 1;
    await fulfillJson(route, 200, { ended: true });
  });

  await page.goto('/query');
  await expect(page.getByRole('button', { name: 'sam@example.com' })).toBeVisible();
  await openTrackedReauthPopup(context, page);
  await advanceClock(page, serverClock, 1_000);
  await expect.poll(() => observes).toBe(1);
  expect(logoutCalls).toBe(0);
  await expect(page).toHaveURL(/\/query$/);
  await advanceClock(page, serverClock, 2_000);
  await expect.poll(() => observes).toBe(2);
  expect(logoutCalls).toBe(0);
  await expect(page).toHaveURL(/\/query$/);
});

test('conditional expiry logout carries the last session id and adopts a concurrently minted session', async ({
  page,
}) => {
  const serverClock = { now: Date.UTC(2026, 6, 23, 12) };
  await installClock(page, serverClock.now);
  await mockCommonApp(page);
  let observes = 0;
  let logoutBody: object | null = null;
  await page.route('**/auth/session/heartbeat', (route) =>
    fulfillJson(route, 200, sessionStatus(serverClock, 1_000, 2 * 60 * 60_000, 41)),
  );
  await page.route('**/auth/session/status', async (route) => {
    observes += 1;
    if (observes === 1) await fulfillJson(route, 401, { reason: 'expired' });
    else await fulfillJson(route, 200, sessionStatus(serverClock, 15 * 60_000, 3 * 60 * 60_000, 42));
  });
  await page.route('**/auth/logout', async (route) => {
    logoutBody = route.request().postDataJSON() as object;
    await fulfillJson(route, 200, { ended: false });
  });

  await page.goto('/query');
  await expect(page.getByRole('button', { name: 'sam@example.com' })).toBeVisible();
  await advanceClock(page, serverClock, 1_000);

  await expect.poll(() => logoutBody).toEqual({ sessionId: 41 });
  await expect.poll(() => observes).toBe(2);
  await expect(page).toHaveURL(/\/query$/);
  await page.getByRole('button', { name: 'sam@example.com' }).click();
  await expect(page.getByText('3h')).toBeVisible();
});

test('idle warning appears at its server-relative lead time and activity dismisses it', async ({ page }) => {
  const serverClock = { now: Date.UTC(2026, 6, 23, 12) };
  await installClock(page, serverClock.now + 5 * 60_000);
  await mockCommonApp(page);
  let touches = 0;
  await page.route('**/auth/session/heartbeat', async (route) => {
    touches += 1;
    const idleAfter = touches === 1 ? 2 * 60_000 : 15 * 60_000;
    await fulfillJson(route, 200, sessionStatus(serverClock, idleAfter, 2 * 60 * 60_000));
  });
  await page.route('**/auth/session/status', (route) =>
    fulfillJson(route, 200, sessionStatus(serverClock, 15 * 60_000, 2 * 60 * 60_000)),
  );

  await page.goto('/query');
  await expect.poll(() => touches).toBe(1);
  await advanceClock(page, serverClock, 60_000);
  await expect(page.getByText('Your session will end soon')).toBeVisible();
  await page.mouse.move(10, 10);
  await expect.poll(() => touches).toBe(2);
  await expect(page.getByText('Your session will end soon')).toBeHidden();
});

test('absolute warning appears at its server-relative lead time', async ({ page }) => {
  const serverClock = { now: Date.UTC(2026, 6, 23, 12) };
  await installClock(page, serverClock.now - 60_000);
  await mockCommonApp(page);
  let touches = 0;
  await page.route('**/auth/session/heartbeat', async (route) => {
    touches += 1;
    await fulfillJson(route, 200, sessionStatus(serverClock, 7 * 60_000, 6 * 60_000));
  });
  await page.route('**/auth/session/status', (route) =>
    fulfillJson(route, 200, sessionStatus(serverClock, 15 * 60_000, 2 * 60 * 60_000)),
  );

  await page.goto('/query');
  await expect.poll(() => touches).toBe(1);
  await advanceClock(page, serverClock, 60_000);

  await expect(page.getByText('Re-authentication required soon')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Re-authenticate' })).toBeVisible();
});

test('a reauth message from an unrelated same-origin sender is ignored', async ({ page }) => {
  const serverClock = { now: Date.UTC(2026, 6, 23, 12) };
  await installClock(page, serverClock.now);
  await mockCommonApp(page);
  let observes = 0;
  await page.route('**/auth/session/heartbeat', (route) =>
    fulfillJson(route, 200, sessionStatus(serverClock, 15 * 60_000, 2 * 60 * 60_000)),
  );
  await page.route('**/auth/session/status', async (route) => {
    observes += 1;
    await fulfillJson(route, 200, sessionStatus(serverClock, 15 * 60_000, 2 * 60 * 60_000));
  });

  await page.goto('/query');
  await expect(page.getByRole('button', { name: 'sam@example.com' })).toBeVisible();
  await page.evaluate(() => window.postMessage({ type: 'pm:reauth-complete' }, window.location.origin));
  await page.waitForTimeout(100);
  expect(observes).toBe(0);
  await expect(page).toHaveURL(/\/query$/);
});

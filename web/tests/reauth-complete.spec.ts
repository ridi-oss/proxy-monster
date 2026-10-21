import { expect, test } from 'playwright/test';

const REAUTH_COMPLETE_PATH = '/auth/reauth-complete';
const REAUTH_COMPLETE_MESSAGE_TYPE = 'pm:reauth-complete';

test('notifies the same-origin opener and closes the popup', async ({ context, page, baseURL }) => {
  await page.route('**/__playwright_blank', (route) =>
    route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>blank</title>' }),
  );
  await page.goto('/__playwright_blank');

  await page.evaluate(() => {
    const target = window as typeof window & {
      reauthMessage?: { type: string; origin: string };
    };
    window.addEventListener('message', (event) => {
      target.reauthMessage = {
        type: (event.data as { type: string }).type,
        origin: event.origin,
      };
    });
  });

  const popupPromise = context.waitForEvent('page');
  await page.evaluate((path) => window.open(path), REAUTH_COMPLETE_PATH);
  const popup = await popupPromise;

  await expect
    .poll(() =>
      page.evaluate(() => {
        const target = window as typeof window & {
          reauthMessage?: { type: string; origin: string };
        };
        return target.reauthMessage;
      }),
    )
    .toEqual({
      type: REAUTH_COMPLETE_MESSAGE_TYPE,
      origin: new URL(baseURL!).origin,
    });
  await expect.poll(() => popup.isClosed()).toBe(true);
});

test('direct navigation leaves the popup completion route', async ({ page }) => {
  await page.goto(REAUTH_COMPLETE_PATH);
  await page.waitForURL((url) => !url.pathname.includes(REAUTH_COMPLETE_PATH));
});

test('filesystem route takes precedence over the auth proxy rewrite', async ({ request }) => {
  const response = await request.get(REAUTH_COMPLETE_PATH);

  expect(response.ok()).toBe(true);
  expect(await response.text()).toContain('data-testid="reauth-complete"');
});

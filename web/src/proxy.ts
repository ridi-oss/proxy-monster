import { NextResponse, type NextRequest } from 'next/server';

import { REAUTH_CALLBACK_PATH } from '@/lib/reauth';

if (process.env.PM_PROXY_TARGET && !process.env.PM_CP_URL) {
  console.warn('PM_PROXY_TARGET is deprecated; set PM_CP_URL instead.');
}

// The control plane's paths go to its base URL, read per request because next.config.ts rewrites are
// frozen at build. The browser then talks same-origin and its httpOnly session cookie flows through.
export function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  if (pathname === REAUTH_CALLBACK_PATH) return NextResponse.next();
  const cpUrl = process.env.PM_CP_URL ?? process.env.PM_PROXY_TARGET ?? 'http://127.0.0.1:41390';
  return NextResponse.rewrite(`${cpUrl.replace(/\/$/, '')}${pathname}${search}`);
}

export const config = { matcher: ['/api/:path*', '/auth/:path*', '/oauth/:path*'] };

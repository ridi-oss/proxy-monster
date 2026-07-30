import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";

import { version } from "./package.json";

const withNextIntl = createNextIntlPlugin("./src/i18n/request.ts");

// Proxy /api and /auth to the Kotlin control-plane (default :41390), so the
// browser talks same-origin and its httpOnly session cookie flows through.
const target = process.env.PM_PROXY_TARGET ?? "http://127.0.0.1:41390";

const nextConfig: NextConfig = {
  // Container images (web/Dockerfile) copy only `.next/standalone` + `.next/static` — the traced,
  // minimal subset of node_modules the built server actually needs — instead of the full
  // node_modules tree. No effect on `next dev`/plain `next start` outside a container.
  output: "standalone",
  // The console shows this on the login page. Read from package.json, which release-please bumps with
  // the server release, so a plain `pnpm build` and a container image report the same version and
  // neither needs a build argument. Inlined at build time, so only the string ships — not package.json.
  env: { NEXT_PUBLIC_APP_VERSION: version },
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${target}/api/:path*` },
      { source: "/auth/:path*", destination: `${target}/auth/:path*` },
    ];
  },
  // The console is never meant to be embedded. It matters most on /device: that page's Continue button
  // approves a pmon login with the viewer's session, so a framed copy would be a clickjacking target for
  // an attacker-prefilled code. Applied site-wide since no page here has a reason to be framed.
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: "frame-ancestors 'none'" },
          { key: "X-Frame-Options", value: "DENY" },
        ],
      },
    ];
  },
  // Next blocks cross-origin dev requests by default (mirrors the old Vite `allowedHosts: true`
  // need). No hostnames ship here — every dev/tunnel domain is different — set
  // PM_WEB_DEV_ORIGINS (comma-separated, in web/.env.local — gitignored, never committed) to
  // whatever you need, e.g. a tailnet host serving this dev server to a remote client. Use `**`
  // (not `*`) for a multi-label wildcard host like `<svc>.<node>.example.com` — Next's
  // allowedDevOrigins matcher only lets a single `*` consume one label (see next/dist/server/
  // app-render/csrf-protection.js matchWildcardDomain), so `*.example.com` silently never matches
  // a two-label subdomain.
  allowedDevOrigins: process.env.PM_WEB_DEV_ORIGINS?.split(",").map((s) => s.trim()).filter(Boolean) ?? [],
};

export default withNextIntl(nextConfig);

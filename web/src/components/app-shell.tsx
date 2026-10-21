'use client';

// The authenticated shell: brand, role-appropriate primary navigation with
// one combined workflow badge, theme and identity controls, and the persistent
// DEBUG pill. Admin stays hidden until coarse permissions explicitly allow it.

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { ShieldHalf } from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { useMePermissions } from '@/lib/hooks';
import { cn } from '@/lib/utils';
import { useWorkflowIncomingRequests } from '@/lib/workflow-requests';
import { ThemeToggle } from '@/components/theme-toggle';
import { LocaleToggle } from '@/components/locale-toggle';
import { IdentityMenu } from '@/components/identity-menu';

export function AppShell({ children }: { children: React.ReactNode }) {
  const t = useTranslations('Nav');
  const pathname = usePathname();
  const { debugMode } = useAuth();
  const { data: permissions, error: permissionsError } = useMePermissions();
  const { count: workflowPendingCount } = useWorkflowIncomingRequests();
  const NAV = [
    { label: t('query'), href: '/query' },
    { label: t('workflows'), href: '/workflows' },
    { label: t('access'), href: '/access' },
    { label: t('audit'), href: '/audit' },
  ] as const;
  const navItems =
    permissionsError == null && permissions?.isAdmin === true ? [...NAV, { label: t('admin'), href: '/admin' }] : NAV;

  return (
    <div className="flex h-svh flex-col">
      <header className="bg-background/80 sticky top-0 z-30 flex h-13 shrink-0 items-center gap-6 border-b px-4 backdrop-blur">
        <Link href="/query" className="flex items-center gap-2">
          <ShieldHalf className="size-4.5" />
          <span className="font-mono text-sm font-semibold tracking-tight">proxy-monster</span>
        </Link>

        <nav aria-label={t('primaryNavigation')} className="flex h-full items-center gap-1">
          {navItems.map((item) => {
            const active = pathname === item.href || pathname.startsWith(item.href + '/');
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? 'page' : undefined}
                className={cn(
                  'relative flex h-full items-center gap-1.5 px-2.5 text-sm transition-colors',
                  active ? 'text-foreground' : 'text-muted-foreground hover:text-foreground',
                )}
              >
                {item.label}
                {item.href === '/workflows' && workflowPendingCount > 0 && (
                  <span
                    data-testid="workflows-pending-count"
                    className="bg-red-500 text-[10px] font-semibold leading-none text-white inline-flex h-4 min-w-4 items-center justify-center rounded-full px-1"
                  >
                    {workflowPendingCount}
                  </span>
                )}
                {active && <span className="bg-foreground absolute inset-x-2.5 -bottom-px h-0.5 rounded-full" />}
              </Link>
            );
          })}
        </nav>

        <div className="ml-auto flex items-center gap-2">
          {debugMode && (
            <span className="rounded-md border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-wider text-red-500">
              DEBUG
            </span>
          )}
          <LocaleToggle />
          <ThemeToggle />
          <IdentityMenu />
        </div>
      </header>

      <main className="flex min-h-0 flex-1 flex-col">{children}</main>
    </div>
  );
}

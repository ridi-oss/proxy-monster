'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { AdminGuard } from '@/components/admin-guard';
import { cn } from '@/lib/utils';

// `labelKey` resolves against the Nav namespace at render (both en + ko catalogs carry every key).
const PRIMARY_NAV = [
  { labelKey: 'datasources', href: '/admin/datasources' },
  { labelKey: 'policies', href: '/admin/policies' },
  { labelKey: 'users', href: '/admin/users' },
  { labelKey: 'groups', href: '/admin/groups' },
] as const;

const POLICY_NAV = [
  { labelKey: 'policyRoles', href: '/admin/policies', exact: true },
  { labelKey: 'policyAssignments', href: '/admin/policies/assignments', exact: false },
  { labelKey: 'policyMaskFns', href: '/admin/policies/mask-fns', exact: false },
  { labelKey: 'policyCedarPolicies', href: '/admin/policies/cedar-policies', exact: false },
] as const;

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const t = useTranslations('Nav');

  return (
    <AdminGuard>
      <div className="flex min-h-0 flex-1">
        <aside className="bg-muted/20 flex w-56 shrink-0 flex-col border-r">
          <div className="border-b px-4 py-4">
            <p className="text-sm font-semibold">{t('admin')}</p>
            <p className="text-muted-foreground mt-0.5 text-xs">{t('adminSubtitle')}</p>
          </div>
          <nav aria-label={t('adminNavLabel')} className="min-h-0 flex-1 overflow-y-auto p-2">
            {PRIMARY_NAV.map((item) => {
              const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
              return (
                <div key={item.href}>
                  <Link
                    href={item.href}
                    aria-current={pathname === item.href ? 'page' : undefined}
                    className={cn(
                      'flex rounded-md px-3 py-2 text-sm font-medium transition-colors',
                      active
                        ? 'bg-accent text-foreground'
                        : 'text-muted-foreground hover:bg-muted/60 hover:text-foreground',
                    )}
                  >
                    {t(item.labelKey)}
                  </Link>
                  {item.href === '/admin/policies' && (
                    <div className="ml-3 border-l py-1 pl-3">
                      {POLICY_NAV.map((policy) => {
                        const policyActive = policy.exact
                          ? pathname === policy.href
                          : pathname === policy.href || pathname.startsWith(`${policy.href}/`);
                        return (
                          <Link
                            key={policy.href}
                            href={policy.href}
                            aria-current={policyActive ? 'page' : undefined}
                            className={cn(
                              'flex rounded-md px-2 py-1.5 text-xs transition-colors',
                              policyActive
                                ? 'bg-accent text-foreground font-medium'
                                : 'text-muted-foreground hover:bg-muted/60 hover:text-foreground',
                            )}
                          >
                            {t(policy.labelKey)}
                          </Link>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </nav>
        </aside>
        <div className="flex min-h-0 min-w-0 flex-1 flex-col">{children}</div>
      </div>
    </AdminGuard>
  );
}

import { AuthGuard } from '@/components/auth-guard';
import { AppShell } from '@/components/app-shell';
import { SessionGuard } from '@/components/session-guard';

/** Authenticated surface: gate on the session, then render the shell + routed page. */
export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGuard>
      <SessionGuard>
        <AppShell>{children}</AppShell>
      </SessionGuard>
    </AuthGuard>
  );
}

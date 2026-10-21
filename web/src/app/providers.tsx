'use client';

import type { ReactNode } from 'react';
import { ThemeProvider } from 'next-themes';
import { AuthProvider } from '@/lib/auth';
import { TooltipProvider } from '@/components/ui/tooltip';
import { Toaster } from '@/components/ui/sonner';

/** Client-side provider stack: theme (dark default), tooltips, auth, toasts. */
export function Providers({ children }: { children: ReactNode }) {
  return (
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem={false} disableTransitionOnChange>
      <TooltipProvider delay={300}>
        <AuthProvider>{children}</AuthProvider>
        <Toaster position="bottom-right" />
      </TooltipProvider>
    </ThemeProvider>
  );
}

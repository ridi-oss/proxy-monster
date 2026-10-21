'use client';

// Editor query history: every run is auto-saved server-side per principal; this dropdown recalls
// recent distinct queries so the user can re-load one into the editor. Refreshes on open.
import { History } from 'lucide-react';
import { useTranslations } from 'next-intl';
import { mutate } from 'swr';
import { useQueryHistory, swrKeys } from '@/lib/hooks';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

function relativeParts(iso: string): { key: string; count: number } {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return { key: 'history.justNow', count: 0 };
  if (s < 3600) return { key: 'history.minutesAgo', count: Math.floor(s / 60) };
  if (s < 86400) return { key: 'history.hoursAgo', count: Math.floor(s / 3600) };
  return { key: 'history.daysAgo', count: Math.floor(s / 86400) };
}

export function QueryHistoryMenu({ onPick }: { onPick: (sql: string) => void }) {
  const t = useTranslations('Query');
  const { data } = useQueryHistory();
  const history = data ?? [];

  const relative = (iso: string): string => {
    const { key, count } = relativeParts(iso);
    return t(key, { count });
  };

  return (
    <DropdownMenu
      onOpenChange={(open) => {
        if (open) mutate(swrKeys.queryHistory);
      }}
    >
      <DropdownMenuTrigger
        render={
          <Button variant="ghost" size="sm" className="gap-1.5">
            <History className="size-3.5" />
            {t('history.button')}
          </Button>
        }
      />
      <DropdownMenuContent align="start" className="max-h-96 w-96 overflow-y-auto">
        <DropdownMenuGroup>
          <DropdownMenuLabel>{t('history.recentQueries')}</DropdownMenuLabel>
          <DropdownMenuSeparator />
          {history.length === 0 ? (
            <DropdownMenuLabel className="text-muted-foreground py-3 font-normal">
              {t('history.empty')}
            </DropdownMenuLabel>
          ) : (
            history.map((h, i) => (
              <DropdownMenuItem
                key={`${h.ranAt}-${i}`}
                onClick={() => onPick(h.sql)}
                className="flex-col items-start gap-0.5"
              >
                <code className="line-clamp-2 w-full font-mono text-xs break-all whitespace-pre-wrap">{h.sql}</code>
                <span className="text-muted-foreground text-[10px]">{relative(h.ranAt)}</span>
              </DropdownMenuItem>
            ))
          )}
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

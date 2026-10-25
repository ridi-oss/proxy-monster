'use client';

import { useState } from 'react';
import { X } from 'lucide-react';
import { cn } from '@/lib/utils';

/** Chip-style multi-value input. Enter or comma adds; Backspace on empty removes the last. */
export function TagsInput({
  value,
  onChange,
  placeholder = 'add…',
  id,
  className,
}: {
  value: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  id?: string;
  className?: string;
}) {
  const [draft, setDraft] = useState('');

  const add = (raw: string) => {
    const t = raw.trim().replace(/,$/, '');
    if (t && !value.includes(t)) onChange([...value, t]);
    setDraft('');
  };
  const remove = (t: string) => onChange(value.filter((x) => x !== t));

  return (
    <div
      className={cn(
        'border-input focus-within:border-ring focus-within:ring-ring/50 flex min-h-9 flex-wrap items-center gap-1.5 rounded-lg border bg-transparent px-2 py-1.5 text-sm transition-[color,box-shadow] focus-within:ring-3',
        className,
      )}
    >
      {value.map((t) => (
        <span
          key={t}
          className="bg-secondary text-secondary-foreground inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 font-mono text-xs"
        >
          {t}
          <button
            type="button"
            onClick={() => remove(t)}
            className="text-muted-foreground hover:text-foreground"
            aria-label={`Remove ${t}`}
          >
            <X className="size-3" />
          </button>
        </span>
      ))}
      <input
        id={id}
        value={draft}
        placeholder={value.length === 0 ? placeholder : ''}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ',') {
            e.preventDefault();
            add(draft);
          } else if (e.key === 'Backspace' && !draft && value.length) {
            remove(value[value.length - 1]);
          }
        }}
        onBlur={() => draft && add(draft)}
        className="placeholder:text-muted-foreground min-w-24 flex-1 bg-transparent outline-none"
      />
    </div>
  );
}

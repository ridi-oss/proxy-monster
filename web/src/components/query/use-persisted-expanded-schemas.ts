'use client';

// Persists schema-group expansion independently for each datasource. Reads happen
// after mount so browser storage never affects the server-rendered tree.
import { useCallback, useEffect, useState } from 'react';

type ExpandedSchemas = Record<string, boolean>;

interface StoredState {
  datasourceId: number;
  expanded: ExpandedSchemas;
}

const keyFor = (datasourceId: number) => `pm.query.expandedSchemas.${datasourceId}`;

function parseStored(raw: string | null): ExpandedSchemas {
  if (raw == null) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed == null || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    if (!Object.values(parsed).every((value) => typeof value === 'boolean')) return {};
    return parsed as ExpandedSchemas;
  } catch {
    return {};
  }
}

export function usePersistedExpandedSchemas(
  datasourceId: number,
): [ExpandedSchemas, (expanded: ExpandedSchemas) => void] {
  const [stored, setStored] = useState<StoredState | null>(null);

  useEffect(() => {
    let expanded: ExpandedSchemas = {};
    try {
      expanded = parseStored(localStorage.getItem(keyFor(datasourceId)));
    } catch {
      /* storage unavailable — default every schema to expanded */
    }
    // Browser-only storage must be applied after mount to avoid a hydration mismatch.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setStored({ datasourceId, expanded });
  }, [datasourceId]);

  const setExpanded = useCallback(
    (expanded: ExpandedSchemas) => {
      setStored({ datasourceId, expanded });
      try {
        localStorage.setItem(keyFor(datasourceId), JSON.stringify(expanded));
      } catch {
        /* storage full / unavailable — keep in-memory state regardless */
      }
    },
    [datasourceId],
  );

  return [stored?.datasourceId === datasourceId ? stored.expanded : {}, setExpanded];
}

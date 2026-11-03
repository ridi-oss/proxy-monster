export function formatConditions(conditions: Record<string, string[]>): string {
  return Object.entries(conditions)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([claim, values]) => `${claim}=${values.join(',')}`)
    .join('\n');
}

export function parseConditions(text: string): Record<string, string[]> | null {
  const out: Record<string, string[]> = {};
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (line === '') continue;
    const eq = line.indexOf('=');
    if (eq <= 0) return null;
    const claim = line.slice(0, eq).trim();
    const values = line
      .slice(eq + 1)
      .split(',')
      .map((v) => v.trim())
      .filter((v) => v !== '');
    if (claim === '' || values.length === 0) return null;
    out[claim] = [...(out[claim] ?? []), ...values];
  }
  return out;
}

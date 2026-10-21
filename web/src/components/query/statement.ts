import type { EditorState } from '@codemirror/state';

/**
 * The range of the statement that Run/Cmd-Enter will execute, given the caret. Statements are
 * `;`-delimited; each segment includes its terminating `;`. The caret belongs to the first segment
 * that ends at or after it (so a caret right after a `;` selects the statement that `;` terminates,
 * not the empty/next one). The returned range is trimmed of surrounding whitespace and still
 * includes the trailing `;` so the highlight covers the whole statement.
 * (Naive on `;` inside string literals — an accepted edge case.)
 */
export function statementRangeAt(state: EditorState): { from: number; to: number } {
  const text = state.doc.toString();
  const pos = state.selection.main.head;

  const segments: Array<[number, number]> = [];
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === ';') {
      segments.push([start, i + 1]);
      start = i + 1;
    }
  }
  segments.push([start, text.length]);

  let chosen: [number, number] = [0, 0];
  for (const [from, to] of segments) {
    const hasText = text.slice(from, to).trim().length > 0;
    if (pos <= to) {
      if (hasText) chosen = [from, to]; // caret here; if blank keep the prior statement
      break;
    }
    if (hasText) chosen = [from, to];
  }

  let [from, to] = chosen;
  while (from < to && /\s/.test(text[from]!)) from++;
  while (to > from && /\s/.test(text[to - 1]!)) to--;
  return { from, to };
}

/** The SQL string to run: the selection if any, else the statement at the caret (terminator stripped). */
export function currentStatement(state: EditorState): string {
  const sel = state.selection.main;
  if (!sel.empty) return state.sliceDoc(sel.from, sel.to);
  const { from, to } = statementRangeAt(state);
  return state.sliceDoc(from, to).replace(/;\s*$/, '').trim();
}

/** Normalize SQL for comparison: drop a trailing `;`, collapse whitespace. */
export function normalizeSql(sql: string): string {
  return sql.trim().replace(/;\s*$/, '').replace(/\s+/g, ' ');
}

/**
 * The range (trimmed, incl. its terminating `;`) of the statement in the doc whose text matches
 * [target] (ignoring whitespace/terminator). Used to highlight the statement a result tab came
 * from. Returns null if no statement matches (e.g. the editor was edited since the run).
 */
export function findStatementRange(state: EditorState, target: string): { from: number; to: number } | null {
  const wanted = normalizeSql(target);
  if (!wanted) return null;
  const text = state.doc.toString();

  const segments: Array<[number, number]> = [];
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === ';') {
      segments.push([start, i + 1]);
      start = i + 1;
    }
  }
  segments.push([start, text.length]);

  for (const [f, t] of segments) {
    let from = f;
    let to = t;
    while (from < to && /\s/.test(text[from]!)) from++;
    while (to > from && /\s/.test(text[to - 1]!)) to--;
    if (to > from && normalizeSql(text.slice(from, to)) === wanted) return { from, to };
  }
  return null;
}

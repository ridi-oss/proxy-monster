import type { EditorState } from '@codemirror/state'

export interface Segment {
  from: number
  to: number
  code: boolean
}

const DOLLAR_TAG = /^\$[A-Za-z_]*\$/

export function statementSegments(text: string): Segment[] {
  const segments: Segment[] = []
  let start = 0
  let code = false
  let i = 0
  const skipQuoted = (quote: string) => {
    i++
    while (i < text.length) {
      const c = text[i]!
      if (c === '\\' && quote !== '`') {
        i += 2
        continue
      }
      if (c === quote) {
        if (text[i + 1] === quote) {
          i += 2
          continue
        }
        i++
        return
      }
      i++
    }
  }
  while (i < text.length) {
    const c = text[i]!
    const next = text[i + 1]
    if (c === '-' && next === '-') {
      const end = text.indexOf('\n', i)
      i = end < 0 ? text.length : end + 1
    } else if (c === '#') {
      const end = text.indexOf('\n', i)
      i = end < 0 ? text.length : end + 1
    } else if (c === '/' && next === '*') {
      const end = text.indexOf('*/', i + 2)
      i = end < 0 ? text.length : end + 2
    } else if (c === "'" || c === '"' || c === '`') {
      code = true
      skipQuoted(c)
    } else if (c === '$' && DOLLAR_TAG.test(text.slice(i, i + 64))) {
      code = true
      const tag = DOLLAR_TAG.exec(text.slice(i, i + 64))![0]
      const end = text.indexOf(tag, i + tag.length)
      i = end < 0 ? text.length : end + tag.length
    } else if (c === ';') {
      segments.push({ from: start, to: i + 1, code })
      i++
      start = i
      code = false
    } else {
      if (!/\s/.test(c)) code = true
      i++
    }
  }
  segments.push({ from: start, to: text.length, code })
  return segments
}

export function countStatements(text: string): number {
  return statementSegments(text).filter((s) => s.code).length
}

function trimRange(text: string, from: number, to: number): { from: number; to: number } {
  while (from < to && /\s/.test(text[from]!)) from++
  while (to > from && /\s/.test(text[to - 1]!)) to--
  return { from, to }
}

/**
 * The range of the statement that Run/Cmd-Enter will execute, given the caret. The caret belongs to
 * the first segment that ends at or after it (so a caret right after a `;` selects the statement that
 * `;` terminates, not the empty/next one). The returned range is trimmed of surrounding whitespace and
 * still includes the trailing `;` so the highlight covers the whole statement.
 */
export function statementRangeAt(state: EditorState): { from: number; to: number } {
  const text = state.doc.toString()
  const pos = state.selection.main.head

  let chosen: Segment = { from: 0, to: 0, code: false }
  for (const segment of statementSegments(text)) {
    if (pos <= segment.to) {
      if (segment.code) chosen = segment // caret here; if blank keep the prior statement
      break
    }
    if (segment.code) chosen = segment
  }
  return trimRange(text, chosen.from, chosen.to)
}

/** The SQL string to run: the selection if any, else the statement at the caret (terminator stripped). */
export function currentStatement(state: EditorState): string {
  const sel = state.selection.main
  if (!sel.empty) return state.sliceDoc(sel.from, sel.to)
  const { from, to } = statementRangeAt(state)
  return state.sliceDoc(from, to).replace(/;\s*$/, '').trim()
}

export type RunTarget =
  | { kind: 'run'; sql: string }
  | { kind: 'selectOne' }
  | { kind: 'useRunAll' }
  | { kind: 'empty' }

export function runTarget(state: EditorState): RunTarget {
  const sel = state.selection.main
  if (sel.empty) {
    if (countStatements(state.doc.toString()) > 1) return { kind: 'selectOne' }
    const sql = currentStatement(state)
    return sql ? { kind: 'run', sql } : { kind: 'empty' }
  }
  const selected = state.sliceDoc(sel.from, sel.to)
  const count = countStatements(selected)
  if (count === 0) return { kind: 'empty' }
  if (count > 1) return { kind: 'useRunAll' }
  return { kind: 'run', sql: selected.trim() }
}

export type RunAllTarget = { kind: 'runAll'; sql: string } | { kind: 'selectAll' } | { kind: 'empty' }

export function runAllTarget(state: EditorState): RunAllTarget {
  const text = state.doc.toString()
  if (countStatements(text) === 0) return { kind: 'empty' }
  const sel = state.selection.main
  const coversAll =
    !sel.empty && text.slice(0, sel.from).trim() === '' && text.slice(sel.to).trim() === ''
  return coversAll ? { kind: 'runAll', sql: text.trim() } : { kind: 'selectAll' }
}

/** Normalize SQL for comparison: drop a trailing `;`, collapse whitespace. */
export function normalizeSql(sql: string): string {
  return sql.trim().replace(/;\s*$/, '').replace(/\s+/g, ' ')
}

/**
 * The range (trimmed, incl. its terminating `;`) of the statement in the doc whose text matches
 * [target] (ignoring whitespace/terminator). Used to highlight the statement a result tab came
 * from. Returns null if no statement matches (e.g. the editor was edited since the run).
 */
export function findStatementRange(state: EditorState, target: string): { from: number; to: number } | null {
  const wanted = normalizeSql(target)
  if (!wanted) return null
  const text = state.doc.toString()
  for (const segment of statementSegments(text)) {
    const { from, to } = trimRange(text, segment.from, segment.to)
    if (to > from && normalizeSql(text.slice(from, to)) === wanted) return { from, to }
  }
  return null
}

const LEADING_COMMENTS = /^(?:\s+|--[^\n]*(?:\n|$)|#[^\n]*(?:\n|$)|\/\*[\s\S]*?\*\/)*/
const TX_START = /^(?:start\s+transaction|begin)\b/i
const TX_END = /^(?:commit|rollback)\b/i

function leadingCode(sql: string): string {
  return sql.replace(LEADING_COMMENTS, '')
}

export function opensTransaction(script: string): boolean {
  const first = statementSegments(script).find((s) => s.code)
  return first != null && TX_START.test(leadingCode(script.slice(first.from, first.to)))
}

export function leavesTransactionOpen(statements: string[]): boolean {
  for (let i = statements.length - 1; i >= 0; i--) {
    const code = leadingCode(statements[i]!)
    if (TX_END.test(code)) return false
    if (TX_START.test(code)) return true
  }
  return false
}

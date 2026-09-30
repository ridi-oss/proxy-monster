import { describe, expect, it } from 'vitest'
import { EditorSelection, EditorState } from '@codemirror/state'
import {
  countStatements,
  findStatementRange,
  leavesTransactionOpen,
  opensTransaction,
  runAllTarget,
  runTarget,
  statementRangeAt,
} from './statement'

function state(doc: string, from: number, to = from) {
  return EditorState.create({ doc, selection: EditorSelection.single(from, to) })
}

describe('countStatements', () => {
  it('counts semicolon-terminated statements', () => {
    expect(countStatements('select 1; select 2;')).toBe(2)
  })

  it('does not split on a semicolon inside a string, identifier, or dollar-quoted body', () => {
    expect(countStatements("select 'a;b', `c;d`, \"e;f\"; select $$ g; h $$")).toBe(2)
  })

  it('does not split on a semicolon inside a comment', () => {
    expect(countStatements('select 1 -- a; b\n; /* c; d */ select 2 # e; f\n')).toBe(2)
  })

  it('ignores an escaped quote when finding the end of a string', () => {
    expect(countStatements("select 'it''s; fine', 'a\\'b;c'")).toBe(1)
  })

  it('does not count empty or comment-only segments', () => {
    expect(countStatements(';; -- only a comment;\n/* and another */;')).toBe(0)
  })
})

describe('runTarget', () => {
  it('runs the statement at the caret when the document holds one statement', () => {
    expect(runTarget(state('select 1;', 3))).toEqual({ kind: 'run', sql: 'select 1' })
  })

  it('requires a selection once the document holds several statements', () => {
    expect(runTarget(state('select 1; select 2;', 3))).toEqual({ kind: 'selectOne' })
  })

  it('runs a selection that holds exactly one statement', () => {
    const doc = 'select 1; select 2;'
    expect(runTarget(state(doc, 10, doc.length))).toEqual({ kind: 'run', sql: 'select 2;' })
  })

  it('refuses a selection of several statements in favour of Run All', () => {
    expect(runTarget(state('select 1; select 2;', 0, 19))).toEqual({ kind: 'useRunAll' })
  })

  it('treats a comment-only selection as nothing to run', () => {
    expect(runTarget(state('-- note\nselect 1;', 0, 7))).toEqual({ kind: 'empty' })
  })
})

describe('runAllTarget', () => {
  const doc = '\nstart transaction;\nupdate t set a = 1;\nrollback;\n'

  it('runs the whole script when everything is selected', () => {
    expect(runAllTarget(state(doc, 0, doc.length))).toEqual({ kind: 'runAll', sql: doc.trim() })
  })

  it('accepts a selection that only leaves surrounding whitespace out', () => {
    expect(runAllTarget(state(doc, 1, doc.length - 1)).kind).toBe('runAll')
  })

  it('requires the whole script to be selected', () => {
    expect(runAllTarget(state(doc, 1)).kind).toBe('selectAll')
    expect(runAllTarget(state(doc, 1, 20)).kind).toBe('selectAll')
  })

  it('keeps comments in the submitted script', () => {
    const commented = 'select 1; -- keep me\nselect 2;'
    expect(runAllTarget(state(commented, 0, commented.length))).toEqual({ kind: 'runAll', sql: commented })
  })
})

describe('statement ranges', () => {
  it('keeps a semicolon inside a string within the statement at the caret', () => {
    const doc = "select 'a;b'; select 2;"
    expect(statementRangeAt(state(doc, 2))).toEqual({ from: 0, to: 13 })
  })

  it('finds a statement whose text holds a quoted semicolon', () => {
    const doc = "select 1; select 'a;b';"
    expect(findStatementRange(state(doc, 0), "select 'a;b'")).toEqual({ from: 10, to: 23 })
  })
})

describe('transaction shape', () => {
  it('sees a script that opens a transaction past its leading comments', () => {
    expect(opensTransaction('-- dry run\n/* x */ START TRANSACTION; update t set a = 1; rollback;')).toBe(true)
    expect(opensTransaction('begin; select 1;')).toBe(true)
  })

  it('sees a script that would autocommit each statement', () => {
    expect(opensTransaction('update t set a = 1; commit;')).toBe(false)
  })

  it('flags a script whose last transaction statement opens one', () => {
    expect(leavesTransactionOpen(['start transaction', 'update t set a = 1'])).toBe(true)
    expect(leavesTransactionOpen(['start transaction', 'update t set a = 1', '-- done\ncommit'])).toBe(false)
    expect(leavesTransactionOpen(['select 1'])).toBe(false)
  })
})

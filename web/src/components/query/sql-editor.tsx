'use client'

import { forwardRef, useEffect, useImperativeHandle, useMemo, useRef } from 'react'
import { useTheme } from 'next-themes'
import CodeMirror, {
  EditorView,
  keymap,
  Prec,
  type ReactCodeMirrorRef,
} from '@uiw/react-codemirror'
import { sql, type SQLNamespace } from '@codemirror/lang-sql'
import { sqlDialect } from './catalog-schema'
import { autocompletion } from '@codemirror/autocomplete'
import { editorTheme } from '@/lib/cm-theme'
import { currentStatement, findStatementRange } from './statement'
import { activeStatementHighlight, linkedQueryHighlight, setLinkedRange } from './statement-highlight'

export interface SqlEditorHandle {
  /** Splice `text` in at the caret (replacing any selection) and refocus. */
  insertAtCursor: (text: string) => void
  /** The query to run: the selection if any, else the `;`-delimited statement under the cursor. */
  currentQuery: () => string
}

interface Props {
  value: string
  onChange: (value: string) => void
  schema: SQLNamespace
  engine?: string
  /** Cmd/Ctrl+Enter handler (run the query). */
  onRun: () => void
  /** SQL of the selected result tab — its matching statement is highlighted + scrolled to. */
  linkedQuery?: string | null
}

export const SqlEditor = forwardRef<SqlEditorHandle, Props>(function SqlEditor(
  { value, onChange, schema, engine, onRun, linkedQuery },
  ref,
) {
  const { resolvedTheme } = useTheme()
  const cmRef = useRef<ReactCodeMirrorRef>(null)
  const onRunRef = useRef(onRun)
  onRunRef.current = onRun

  // Keep the linked-statement highlight in sync with the active result tab + the doc.
  useEffect(() => {
    const view = cmRef.current?.view
    if (!view) return
    const range = linkedQuery ? findStatementRange(view.state, linkedQuery) : null
    view.dispatch({ effects: setLinkedRange.of(range) })
  }, [linkedQuery, value])

  // Scroll the linked statement into view when the selected tab changes (not on every keystroke).
  useEffect(() => {
    const view = cmRef.current?.view
    if (!view || !linkedQuery) return
    const range = findStatementRange(view.state, linkedQuery)
    if (range) view.dispatch({ effects: EditorView.scrollIntoView(range.from, { y: 'center' }) })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [linkedQuery])

  useImperativeHandle(ref, () => ({
    insertAtCursor(text: string) {
      const view = cmRef.current?.view
      if (!view) return
      const { from, to } = view.state.selection.main
      view.dispatch({
        changes: { from, to, insert: text },
        selection: { anchor: from + text.length },
      })
      view.focus()
    },
    currentQuery(): string {
      const view = cmRef.current?.view
      if (!view) return value
      return currentStatement(view.state)
    },
  }))

  // Stable across keystrokes — a fresh array/object identity here makes
  // @uiw/react-codemirror reconfigure the whole editor on every render (the
  // typing lag). Recompute only when the schema or theme actually changes.
  const extensions = useMemo(
    () => [
      editorTheme(resolvedTheme),
      Prec.highest(
        keymap.of([
          {
            key: 'Mod-Enter',
            run: () => {
              onRunRef.current()
              return true
            },
          },
        ]),
      ),
      sql({ dialect: sqlDialect(engine), schema, upperCaseKeywords: true }),
      activeStatementHighlight,
      linkedQueryHighlight,
      // Tuned autocomplete: debounce so the popup doesn't recompute/repaint on every keystroke,
      // and cap rendered options so the list paints cheaply. (basicSetup's default autocompletion
      // is disabled in BASIC_SETUP so this is the only one.)
      autocompletion({ activateOnTypingDelay: 150, interactionDelay: 100, maxRenderedOptions: 15 }),
      EditorView.lineWrapping,
    ],
    [schema, engine, resolvedTheme],
  )

  return (
    <CodeMirror
      ref={cmRef}
      value={value}
      onChange={onChange}
      theme="none"
      extensions={extensions}
      height="100%"
      style={EDITOR_STYLE}
      placeholder="SELECT * FROM users LIMIT 100;"
      basicSetup={BASIC_SETUP}
    />
  )
})

// Hoisted so their identity is stable (passing fresh object literals reconfigures the editor).
const EDITOR_STYLE = { height: '100%', fontSize: 13 }
const BASIC_SETUP = {
  lineNumbers: true,
  foldGutter: false,
  highlightActiveLine: true,
  autocompletion: false, // we supply a tuned autocompletion() extension instead
}

import { Decoration, type DecorationSet, EditorView, ViewPlugin, type ViewUpdate } from '@codemirror/view';
import { RangeSetBuilder, StateEffect, StateField } from '@codemirror/state';
import { statementRangeAt } from './statement';

// Subtly highlights the statement that Run / Cmd-Enter will execute (the one at the caret). When
// there's a selection, that selection runs and CodeMirror already highlights it, so we draw nothing.
const statementMark = Decoration.mark({ class: 'cm-active-statement' });

function build(view: EditorView): DecorationSet {
  const builder = new RangeSetBuilder<Decoration>();
  if (view.state.selection.main.empty) {
    const { from, to } = statementRangeAt(view.state);
    if (to > from) builder.add(from, to, statementMark);
  }
  return builder.finish();
}

export const activeStatementHighlight = ViewPlugin.fromClass(
  class {
    decorations: DecorationSet;
    constructor(view: EditorView) {
      this.decorations = build(view);
    }
    update(u: ViewUpdate) {
      if (u.docChanged || u.selectionSet) this.decorations = build(u.view);
    }
  },
  { decorations: (v) => v.decorations },
);

// ---- Linked-query highlight: the statement a selected result tab came from ----

/** Set (or clear, with null) the editor range linked to the active result tab. */
export const setLinkedRange = StateEffect.define<{ from: number; to: number } | null>();

const linkedLine = Decoration.line({ class: 'cm-linked-line' });

function linkedLines(
  state: { doc: { lineAt: (p: number) => { from: number; to: number }; length: number } },
  range: { from: number; to: number } | null,
): DecorationSet {
  if (!range || range.to <= range.from) return Decoration.none;
  const builder = new RangeSetBuilder<Decoration>();
  let pos = range.from;
  while (true) {
    const line = state.doc.lineAt(pos);
    builder.add(line.from, line.from, linkedLine);
    if (line.to >= range.to) break;
    pos = line.to + 1;
    if (pos > state.doc.length) break;
  }
  return builder.finish();
}

/** A left-bar line decoration marking the statement that produced the active result tab. */
export const linkedQueryHighlight = StateField.define<DecorationSet>({
  create() {
    return Decoration.none;
  },
  update(deco, tr) {
    let next = deco.map(tr.changes);
    for (const e of tr.effects) {
      if (e.is(setLinkedRange)) next = linkedLines(tr.state, e.value);
    }
    return next;
  },
  provide: (f) => EditorView.decorations.from(f),
});

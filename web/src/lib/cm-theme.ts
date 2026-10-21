// Two CodeMirror themes (dark + light) tuned to the app palette so the editor
// matches the Vercel canvas in either mode. Chrome is mostly transparent (it
// inherits the surrounding panel background); only the syntax palette and a few
// affordances (cursor, selection, gutter, active line, autocomplete popup) are
// set. Pick one with `editorTheme(resolvedTheme)`.

import { EditorView } from '@codemirror/view';
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language';
import { tags as t } from '@lezer/highlight';
import type { Extension } from '@codemirror/state';

interface Palette {
  fg: string;
  cursor: string;
  selection: string;
  gutter: string;
  activeLine: string;
  activeStatement: string;
  linked: string;
  popupBg: string;
  popupBorder: string;
  keyword: string;
  string: string;
  number: string;
  comment: string;
  func: string;
  type: string;
  punct: string;
}

function build(dark: boolean, c: Palette): Extension {
  const chrome = EditorView.theme(
    {
      '&': { color: c.fg, backgroundColor: 'transparent', height: '100%' },
      '.cm-scroller': {
        fontFamily: 'var(--font-mono)',
        lineHeight: '1.6',
      },
      '.cm-content': { caretColor: c.cursor, padding: '8px 0' },
      '.cm-cursor, .cm-dropCursor': { borderLeftColor: c.cursor, borderLeftWidth: '1.5px' },
      '&.cm-focused': { outline: 'none' },
      '&.cm-focused .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection': {
        backgroundColor: c.selection,
      },
      '.cm-gutters': {
        backgroundColor: 'transparent',
        color: c.gutter,
        border: 'none',
        fontSize: '12px',
      },
      '.cm-lineNumbers .cm-gutterElement': { padding: '0 10px 0 16px' },
      '.cm-activeLine': { backgroundColor: c.activeLine },
      // The statement Run/Cmd-Enter will execute (see statement-highlight.ts).
      '.cm-active-statement': { backgroundColor: c.activeStatement, borderRadius: '2px' },
      // The statement the selected result tab came from (left accent bar).
      '.cm-linked-line': { boxShadow: `inset 2px 0 0 0 ${c.linked}` },
      '.cm-activeLineGutter': { backgroundColor: 'transparent', color: c.fg },
      '.cm-selectionMatch': { backgroundColor: c.selection },
      '.cm-tooltip': {
        backgroundColor: c.popupBg,
        border: `1px solid ${c.popupBorder}`,
        borderRadius: '8px',
        overflow: 'hidden',
        boxShadow: '0 8px 24px rgba(0,0,0,0.25)',
      },
      '.cm-tooltip.cm-tooltip-autocomplete > ul': { fontFamily: 'var(--font-mono)', fontSize: '12px' },
      '.cm-tooltip-autocomplete > ul > li': { padding: '3px 10px' },
      '.cm-tooltip-autocomplete > ul > li[aria-selected]': {
        backgroundColor: c.selection,
        color: c.fg,
      },
      '.cm-completionIcon': { opacity: '0.6', paddingRight: '0.6em' },
    },
    { dark },
  );

  const highlight = HighlightStyle.define([
    { tag: [t.keyword, t.modifier, t.operatorKeyword, t.controlKeyword], color: c.keyword, fontWeight: '500' },
    { tag: [t.string, t.special(t.string), t.regexp], color: c.string },
    { tag: [t.number, t.bool, t.null, t.atom], color: c.number },
    { tag: [t.comment, t.lineComment, t.blockComment], color: c.comment, fontStyle: 'italic' },
    { tag: [t.function(t.variableName), t.function(t.propertyName), t.standard(t.name)], color: c.func },
    { tag: [t.typeName, t.tagName, t.className], color: c.type },
    { tag: [t.operator, t.punctuation, t.separator, t.bracket], color: c.punct },
    { tag: [t.propertyName, t.attributeName, t.variableName, t.name], color: c.fg },
  ]);

  return [chrome, syntaxHighlighting(highlight)];
}

const DARK = build(true, {
  fg: '#e6e6e6',
  cursor: '#e6e6e6',
  selection: 'rgba(255,255,255,0.13)',
  gutter: '#5a5a5a',
  activeLine: 'rgba(255,255,255,0.035)',
  activeStatement: 'rgba(129,140,248,0.16)',
  linked: '#34d399',
  popupBg: '#18181b',
  popupBorder: 'rgba(255,255,255,0.12)',
  keyword: '#c4b5fd',
  string: '#86efac',
  number: '#fcd34d',
  comment: '#71717a',
  func: '#7dd3fc',
  type: '#5eead4',
  punct: '#a1a1aa',
});

const LIGHT = build(false, {
  fg: '#18181b',
  cursor: '#18181b',
  selection: 'rgba(0,0,0,0.10)',
  gutter: '#a1a1aa',
  activeLine: 'rgba(0,0,0,0.03)',
  activeStatement: 'rgba(79,70,229,0.12)',
  linked: '#059669',
  popupBg: '#ffffff',
  popupBorder: 'rgba(0,0,0,0.10)',
  keyword: '#7c3aed',
  string: '#15803d',
  number: '#b45309',
  comment: '#71717a',
  func: '#0369a1',
  type: '#0f766e',
  punct: '#71717a',
});

export function editorTheme(resolved: string | undefined): Extension {
  return resolved === 'light' ? LIGHT : DARK;
}

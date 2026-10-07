package main

import (
	"context"
	"strconv"
	"strings"
	"sync"

	"fyne.io/systray"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// node is a menu item on screen and the action a click on it runs. The action is swapped under mu whenever
// the item is updated in place, so a click never runs an action from an older render.
type node struct {
	item *systray.MenuItem
	mu   sync.Mutex
	act  *action
}

func (n *node) action() *action {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.act
}

// render shows one daemon status. A nil status means no daemon is reachable, which is a state to display,
// never a stale last-known one.
func (a *app) render(s *control.Status) {
	a.renderMu.Lock()
	defer a.renderMu.Unlock()
	a.mu.Lock()
	a.status = s
	a.mu.Unlock()
	a.redraw()
}

// redraw rebuilds the menu from the last status. Callers hold renderMu.
func (a *app) redraw() {
	a.mu.Lock()
	s := a.status
	a.mu.Unlock()
	v := a.view()
	menu := buildMenu(s, v)
	a.noticeEndings(s, v)
	go a.refreshAI(false)
	if !a.onScreen {
		return
	}
	icon := stateIcons[iconFor(s, v)]
	systray.SetTemplateIcon(icon, regularIcon(icon))
	systray.SetTooltip(tooltip(menu))

	shape := shapeOf(menu)
	if shape != a.shape || !a.update(menu, a.nodes) {
		a.rebuild(menu)
		a.shape = shape
	}
}

func tooltip(menu []entry) string {
	var parts []string
	for _, e := range menu {
		if e.key == "header" || strings.HasPrefix(e.key, "srv:") {
			parts = append(parts, e.title)
		}
	}
	return "Proxy Monster\n" + strings.Join(parts, "\n")
}

// shapeOf is the menu's keys in order. Titles, checkmarks and payloads change in place; anything else rebuilds.
func shapeOf(menu []entry) string {
	var b strings.Builder
	var walk func([]entry)
	walk = func(es []entry) {
		for _, e := range es {
			b.WriteString(strconv.Quote(e.key))
			if len(e.children) > 0 {
				b.WriteByte('[')
				walk(e.children)
				b.WriteByte(']')
			}
			b.WriteByte(',')
		}
	}
	walk(menu)
	return b.String()
}

// rebuild replaces every item. systray appends items in creation order and cannot insert, so a change in shape
// is a reset; the click watchers of the old items stop with their generation's context.
func (a *app) rebuild(menu []entry) {
	if a.genCancel != nil {
		a.genCancel()
	}
	ctx, cancel := context.WithCancel(a.ctx)
	a.genCancel = cancel
	systray.ResetMenu()
	a.children = map[*node][]*node{}
	a.nodes = a.add(ctx, nil, menu)
}

func (a *app) add(ctx context.Context, parent *systray.MenuItem, es []entry) []*node {
	nodes := make([]*node, len(es))
	for i, e := range es {
		if e.sep {
			if parent == nil {
				systray.AddSeparator()
			} else {
				parent.AddSeparator()
			}
			nodes[i] = &node{}
			continue
		}
		var item *systray.MenuItem
		switch {
		case parent == nil && e.checkbox:
			item = systray.AddMenuItemCheckbox(e.title, "", e.checked)
		case parent == nil:
			item = systray.AddMenuItem(e.title, "")
		case e.checkbox:
			item = parent.AddSubMenuItemCheckbox(e.title, "", e.checked)
		default:
			item = parent.AddSubMenuItem(e.title, "")
		}
		if e.disabled {
			item.Disable()
		}
		n := &node{item: item, act: e.act}
		nodes[i] = n
		if len(e.children) > 0 {
			a.children[n] = a.add(ctx, item, e.children)
		}
		go a.watchClicks(ctx, n)
	}
	return nodes
}

// update applies a menu of the same shape in place, reporting false if the items on screen do not match it.
func (a *app) update(es []entry, nodes []*node) bool {
	if len(es) != len(nodes) {
		return false
	}
	for i, e := range es {
		n := nodes[i]
		if e.sep || n.item == nil {
			continue
		}
		n.item.SetTitle(e.title)
		if e.disabled {
			n.item.Disable()
		} else {
			n.item.Enable()
		}
		if e.checkbox {
			if e.checked {
				n.item.Check()
			} else {
				n.item.Uncheck()
			}
		}
		n.mu.Lock()
		n.act = e.act
		n.mu.Unlock()
		if len(e.children) > 0 && !a.update(e.children, a.children[n]) {
			return false
		}
	}
	return true
}

func (a *app) watchClicks(ctx context.Context, n *node) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-n.item.ClickedCh:
			// systray closes ClickedCh when ResetMenu removes the item; that is not a click.
			if !ok || ctx.Err() != nil {
				return
			}
			if act := n.action(); act != nil {
				go a.run(*act)
			}
		}
	}
}

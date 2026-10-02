'use client'

// Schema/table/column explorer for the editor's left rail (BigQuery-style).
// Schemas and tables are collapsible; `pii`-tagged columns are flagged loud
// (red dot), any other tag amber. Clicking a row selects it; a schema or table row also
// toggles, a table opens its tab, and a column opens its table's tab with the column flashed.
import { createContext, useContext, useMemo, useState } from 'react'
import { useTranslations } from 'next-intl'
import { toast } from 'sonner'
import {
  Check,
  ChevronRight,
  ChevronsDownUp,
  ChevronsUpDown,
  Database,
  Copy,
  KeyRound,
  Search,
  Settings2,
  Table2,
  TextCursorInput,
  X,
} from 'lucide-react'
import { schemaKey } from '@/lib/catalog'
import { copyText } from '@/lib/clipboard'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import type { TreeColumn, TreeTable } from './catalog-schema'
import { usePersistedExpandedSchemas } from './use-persisted-expanded-schemas'
import { usePersistedFlag } from './use-persisted-flag'

interface Props {
  datasourceId: number
  tables: TreeTable[]
  /** Insert a name at the caret. Without it, tables are leaves and columns never show. */
  onInsert?: (text: string) => void
  onOpenTable: (table: TreeTable) => void
  onSelectColumn?: (table: TreeTable, column: string) => void
  /** Schemas that start expanded (the search path); the rest start collapsed. Unset or unmatched: all expanded. */
  defaultSchemas?: string[]
  currentCatalog?: string | null
}

interface VisibleTable {
  table: TreeTable
  columns: TreeColumn[]
  /** Only some of its columns match the filter, so it opens to show them. */
  columnMatch: boolean
}

interface SchemaGroup {
  key: string
  catalog: string
  label: string
  schema: string
  system: boolean
  tables: VisibleTable[]
}

type Expansion = Record<string, boolean>

interface TreeContext {
  query: string
  onInsert?: (text: string) => void
  onOpenTable: (table: TreeTable) => void
  onSelectColumn?: (table: TreeTable, column: string) => void
  // A marker the user sets by clicking a row; independent of whatever tab or panel is showing.
  selected: string | null
  select: (id: string) => void
}
const Tree = createContext<TreeContext>({ query: '', onOpenTable: () => {}, selected: null, select: () => {} })
const SELECTED = 'bg-primary/15 font-medium'

function useSelection(id: string) {
  const { selected, select } = useContext(Tree)
  return { selected: selected === id, select: () => select(id) }
}

export function SchemaTree({
  datasourceId, tables, onInsert, onOpenTable, onSelectColumn, defaultSchemas, currentCatalog,
}: Props) {
  const t = useTranslations('Query')
  const withColumns = onInsert != null
  const [filter, setFilter] = useState('')
  const [showSystem, setShowSystem] = usePersistedFlag('pm.query.showSystemSchemas', false)
  const [expandedSchemas, setExpandedSchemas] = usePersistedExpandedSchemas(datasourceId)
  const [openTables, setOpenTables] = useState<Expansion>({})
  const [selected, setSelected] = useState<string | null>(null)
  // Expansion while filtering is separate and starts over with each new filter.
  const [filterExpansion, setFilterExpansion] = useState<{ filter: string; open: Expansion }>({ filter: '', open: {} })
  const query = filter.trim().toLowerCase()
  const filterOpen = filterExpansion.filter === query ? filterExpansion.open : {}
  const context = useMemo<TreeContext>(
    () => ({ query, onInsert, onOpenTable, onSelectColumn, selected, select: setSelected }),
    [query, onInsert, onOpenTable, onSelectColumn, selected],
  )

  const { groups, hiddenSystemSchemas } = useMemo(() => {
    const bySchema = new Map<string, SchemaGroup>()
    const hidden = new Set<string>()
    const multipleCatalogs = new Set(tables.map((table) => table.catalog)).size > 1

    for (const table of tables) {
      const key = schemaKey(table.catalog, table.schema)
      if (table.system && !showSystem) {
        hidden.add(key)
        continue
      }
      let columns = table.columns
      let columnMatch = false
      if (query) {
        const schemaMatches = table.schema.toLowerCase().includes(query) || table.catalog.toLowerCase().includes(query)
        const tableMatches =
          table.name.toLowerCase().includes(query) || table.qualified.toLowerCase().includes(query)
        if (!schemaMatches && !tableMatches) {
          if (!withColumns) continue
          columns = table.columns.filter((column) => column.name.toLowerCase().includes(query))
          if (columns.length === 0) continue
          columnMatch = true
        }
      }

      let group = bySchema.get(key)
      if (!group) {
        group = {
          key, catalog: table.catalog, schema: table.schema, system: table.system,
          label: multipleCatalogs ? `${table.schema} (${table.catalog})` : table.schema,
          tables: [],
        }
        bySchema.set(key, group)
      }
      group.tables.push({ table, columns, columnMatch })
    }

    return { groups: [...bySchema.values()], hiddenSystemSchemas: hidden.size }
  }, [tables, query, showSystem, withColumns])

  const defaultOpen = useMemo(() => {
    const keys = new Set(
      tables
        .filter((table) => !table.system && defaultSchemas?.includes(table.schema)
          && (currentCatalog == null || table.catalog === currentCatalog))
        .map((table) => schemaKey(table.catalog, table.schema)),
    )
    return keys.size > 0 ? keys : null
  }, [tables, defaultSchemas, currentCatalog])

  const schemaOpen = (key: string) =>
    query ? filterOpen[key] ?? true : expandedSchemas[key] ?? (defaultOpen?.has(key) ?? true)
  const tableOpen = (visible: VisibleTable) =>
    query ? filterOpen[visible.table.key] ?? visible.columnMatch : openTables[visible.table.key] === true

  const setFilterOpen = (open: Expansion) => setFilterExpansion({ filter: query, open })

  const toggleSchema = (key: string) => {
    if (query) setFilterOpen({ ...filterOpen, [key]: !schemaOpen(key) })
    else setExpandedSchemas({ ...expandedSchemas, [key]: !schemaOpen(key) })
  }
  const toggleTable = (visible: VisibleTable) => {
    const key = visible.table.key
    if (query) setFilterOpen({ ...filterOpen, [key]: !tableOpen(visible) })
    else setOpenTables({ ...openTables, [key]: !tableOpen(visible) })
  }

  const setAll = (open: boolean) => {
    if (query) {
      const next: Expansion = {}
      for (const group of groups) {
        next[group.key] = open
        for (const { table } of group.tables) next[table.key] = open
      }
      setFilterOpen(next)
      return
    }
    setExpandedSchemas({ ...expandedSchemas, ...Object.fromEntries(groups.map((group) => [group.key, open])) })
    setOpenTables(open ? Object.fromEntries(groups.flatMap((group) => group.tables.map(({ table }) => [table.key, true]))) : {})
  }

  return (
    <div data-testid="schema-tree" className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-center gap-0.5 p-2">
        <div className="relative min-w-0 flex-1">
          <Search className="text-muted-foreground pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2" />
          <Input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape' && filter) {
                e.preventDefault()
                setFilter('')
              }
            }}
            placeholder={t(withColumns ? 'schema.filterPlaceholder' : 'schema.filterTablesPlaceholder')}
            aria-label={t(withColumns ? 'schema.filterPlaceholder' : 'schema.filterTablesPlaceholder')}
            className={cn('h-7 pl-7 text-xs', filter && 'pr-7')}
          />
          {filter && (
            <button
              type="button"
              onClick={() => setFilter('')}
              aria-label={t('schema.clearFilter')}
              title={t('schema.clearFilter')}
              className="text-muted-foreground hover:text-foreground hover:bg-accent absolute top-1/2 right-1 flex size-5 -translate-y-1/2 items-center justify-center rounded"
            >
              <X className="size-3.5" />
            </button>
          )}
        </div>
        <TreeAction label={t('schema.expandAll')} onClick={() => setAll(true)}>
          <ChevronsUpDown className="size-3.5" />
        </TreeAction>
        <TreeAction label={t('schema.collapseAll')} onClick={() => setAll(false)}>
          <ChevronsDownUp className="size-3.5" />
        </TreeAction>
        <DropdownMenu>
          <Tooltip>
            <TooltipTrigger
              render={
                <DropdownMenuTrigger
                  render={<Button variant="ghost" size="icon-xs" aria-label={t('schema.viewOptions')} />}
                />
              }
            >
              <Settings2 className="size-3.5" />
            </TooltipTrigger>
            <TooltipContent>{t('schema.viewOptions')}</TooltipContent>
          </Tooltip>
          <DropdownMenuContent align="end" className="w-52">
            <DropdownMenuCheckboxItem checked={showSystem} onCheckedChange={setShowSystem}>
              {t('schema.showSystemSchemas')}
            </DropdownMenuCheckboxItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
      <div
        className="min-h-0 flex-1 overflow-y-auto px-1 pb-2"
        onClick={(e) => {
          if (!(e.target as Element).closest('[data-tree-node]')) setSelected(null)
        }}
      >
        <Tree.Provider value={context}>
          {groups.length === 0 && (query || hiddenSystemSchemas === 0) ? (
            <p className="text-muted-foreground px-3 py-2 text-xs">
              {t(withColumns ? 'schema.noMatch' : 'schema.noTableMatch')}
            </p>
          ) : (
            groups.map((group) => (
              <SchemaGroupNode
                key={group.key}
                group={group}
                expanded={schemaOpen(group.key)}
                tableOpen={tableOpen}
                onToggle={() => toggleSchema(group.key)}
                onToggleTable={toggleTable}
              />
            ))
          )}
        </Tree.Provider>
        {hiddenSystemSchemas > 0 && (
          <p className="text-muted-foreground px-3 pt-2 text-[11px]">
            {t('schema.systemHidden', { count: hiddenSystemSchemas })}{' '}
            <button
              type="button"
              onClick={() => setShowSystem(true)}
              className="hover:text-foreground underline underline-offset-2"
            >
              {t('schema.show')}
            </button>
          </p>
        )}
      </div>
    </div>
  )
}

function TreeAction({ label, onClick, children }: { label: string; onClick: () => void; children: React.ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger render={<Button variant="ghost" size="icon-xs" aria-label={label} onClick={onClick} />}>
        {children}
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}

/** Marks every case-insensitive occurrence of `query` in `text`. */
export function Highlight({ text, query }: { text: string; query: string }) {
  if (!query) return text
  const lower = text.toLowerCase()
  const parts: React.ReactNode[] = []
  let from = 0
  for (let at = lower.indexOf(query); at !== -1; at = lower.indexOf(query, from)) {
    if (at > from) parts.push(text.slice(from, at))
    parts.push(
      <mark key={at} className="rounded-sm bg-yellow-400/40 text-inherit dark:bg-yellow-300/30">
        {text.slice(at, at + query.length)}
      </mark>,
    )
    from = at + query.length
  }
  if (from === 0) return text
  parts.push(text.slice(from))
  return parts
}

function SchemaGroupNode({
  group,
  expanded,
  tableOpen,
  onToggle,
  onToggleTable,
}: {
  group: SchemaGroup
  expanded: boolean
  tableOpen: (visible: VisibleTable) => boolean
  onToggle: () => void
  onToggleTable: (visible: VisibleTable) => void
}) {
  const t = useTranslations('Query')
  const { query } = useContext(Tree)
  const { selected, select } = useSelection(group.key)
  return (
    <div
      data-testid="schema-group"
      data-catalog={group.catalog}
      data-schema={group.schema}
      data-system={group.system || undefined}
    >
      <Row
        selected={selected}
        onClick={() => {
          select()
          onToggle()
        }}
        toggle={{
          open: expanded,
          label: expanded
            ? t('schema.collapseSchema', { schema: group.label })
            : t('schema.expandSchema', { schema: group.label }),
        }}
        icon={<Database className="text-muted-foreground size-3.5 shrink-0" />}
        label={<Highlight text={group.label} query={query} />}
        labelClassName={cn('font-medium', group.system && 'text-muted-foreground')}
        title={t('schema.schemaTitle', { schema: group.label })}
        aside={<span className="text-muted-foreground/70 shrink-0 font-mono text-[10px]">{group.tables.length}</span>}
        name={group.tables[0]?.table.schemaRef ?? group.schema}
        insertable={group.tables[0]?.table.insert != null}
      />
      {expanded && (
        <div className="ml-[14px] border-l pl-2">
          {group.tables.map((visible) => (
            <TableNode
              key={visible.table.key}
              visible={visible}
              open={tableOpen(visible)}
              onToggle={() => onToggleTable(visible)}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function TableNode({ visible: { table, columns }, open, onToggle }: {
  visible: VisibleTable
  open: boolean
  onToggle: () => void
}) {
  const t = useTranslations('Query')
  const { query, onInsert, onOpenTable } = useContext(Tree)
  const { selected, select } = useSelection(table.key)
  const withColumns = onInsert != null

  return (
    <div
      data-testid="schema-table"
      data-catalog={table.catalog}
      data-schema={table.schema}
      data-table={table.name}
    >
      <Row
        selected={selected}
        onClick={() => {
          select()
          onOpenTable(table)
          if (withColumns) onToggle()
        }}
        toggle={withColumns ? {
          open,
          label: open
            ? t('schema.collapseTable', { table: table.qualified })
            : t('schema.expandTable', { table: table.qualified }),
          onToggle: () => {
            select()
            onToggle()
          },
        } : undefined}
        icon={<Table2 className="text-muted-foreground size-3.5 shrink-0" />}
        label={<Highlight text={table.name} query={query} />}
        title={t('schema.openTableTitle', { table: table.qualified })}
        aside={
          <>
            {!withColumns && (
              <span className="text-muted-foreground/70 shrink-0 font-mono text-[10px]">{table.columns.length}</span>
            )}
            {table.piiCount > 0 && (
              <span className="shrink-0 rounded border border-red-500/25 bg-red-500/10 px-1 py-px font-mono text-[10px] text-red-500">
                {t('schema.piiBadge', { count: table.piiCount })}
              </span>
            )}
          </>
        }
        name={table.ref}
        insertable={table.insert != null}
      />
      {withColumns && open && (
        <div className="ml-[14px] border-l pl-2">
          {columns.map((column) => (
            <ColumnRow key={column.name} table={table} column={column} />
          ))}
        </div>
      )}
    </div>
  )
}

function ColumnRow({ table, column }: { table: TreeTable; column: TreeColumn }) {
  const t = useTranslations('Query')
  const { query, onSelectColumn } = useContext(Tree)
  const { selected, select } = useSelection(JSON.stringify([table.key, column.name]))
  // Any tag makes a column classified; `pii` keeps the louder icon as the common case.
  const pii = column.tags.includes('pii')
  const sensitive = column.tags.length > 0
  return (
    <Row
      selected={selected}
      onClick={() => {
        select()
        onSelectColumn?.(table, column.name)
      }}
      icon={
        pii ? (
          <KeyRound className="size-3 shrink-0 text-red-500" />
        ) : (
          <span
            className={cn(
              'mx-[3px] size-1.5 shrink-0 rounded-full',
              sensitive ? 'bg-amber-500' : 'bg-muted-foreground/30',
            )}
          />
        )
      }
      label={<Highlight text={column.name} query={query} />}
      labelClassName={cn(pii && 'text-red-500')}
      title={
        t('schema.columnTitle', { name: column.name, type: column.dataType }) +
        (column.nullable ? '' : t('schema.notNullSuffix'))
      }
      aside={
        <span className="text-muted-foreground/70 shrink-0 truncate font-mono text-[10px] lowercase">
          {column.dataType}
        </span>
      }
      name={column.ref}
      insertable={table.insert != null}
    />
  )
}

/** One tree row: the row click is the node's action; copy/insert show on hover and act on `name`. */
function Row({
  selected, onClick, toggle, icon, label, labelClassName, title, aside, name, insertable,
}: {
  selected: boolean
  onClick: () => void
  toggle?: { open: boolean; label: string; onToggle?: () => void }
  icon: React.ReactNode
  label: React.ReactNode
  labelClassName?: string
  title: string
  aside?: React.ReactNode
  name: string
  /** False for a table outside the current catalog: its name would resolve elsewhere in the editor. */
  insertable: boolean
}) {
  return (
    <div
      data-tree-node
      onClick={onClick}
      className={cn(
        'group flex cursor-default items-center gap-1 rounded-md pr-1 pl-1',
        selected ? SELECTED : 'hover:bg-accent',
      )}
    >
      {toggle ? (
        <button
          type="button"
          aria-expanded={toggle.open}
          aria-label={toggle.label}
          onClick={toggle.onToggle && ((e) => {
            e.stopPropagation()
            toggle.onToggle?.()
          })}
          className="text-muted-foreground flex size-5 shrink-0 items-center justify-center"
        >
          <ChevronRight className={cn('size-3.5 transition-transform', toggle.open && 'rotate-90')} />
        </button>
      ) : (
        <span className="w-1 shrink-0" />
      )}
      {icon}
      <button
        type="button"
        title={title}
        aria-current={selected || undefined}
        className={cn('min-w-0 flex-1 truncate py-1 text-left font-mono text-xs', labelClassName)}
      >
        {label}
      </button>
      {aside}
      <RowActions name={name} insertable={insertable} />
    </div>
  )
}

function RowActions({ name, insertable }: { name: string; insertable: boolean }) {
  const t = useTranslations('Query')
  const { onInsert } = useContext(Tree)
  const [copied, setCopied] = useState(false)
  const action = 'text-muted-foreground hover:text-foreground hover:bg-background flex size-5 shrink-0 items-center justify-center rounded'
  return (
    <span className="hidden shrink-0 items-center group-hover:flex group-has-[:focus-visible]:flex">
      <button
        type="button"
        aria-label={copied ? t('schema.copied') : t('schema.copyName', { name })}
        title={copied ? t('schema.copied') : t('schema.copyName', { name })}
        onClick={(e) => {
          e.stopPropagation()
          copyText(name).then(
            () => {
              setCopied(true)
              window.setTimeout(() => setCopied(false), 1500)
            },
            () => toast.error(t('schema.copyFailed')),
          )
        }}
        className={action}
      >
        {copied ? <Check className="size-3" /> : <Copy className="size-3" />}
      </button>
      {onInsert && insertable && (
        <button
          type="button"
          aria-label={t('schema.insertName', { name })}
          title={t('schema.insertName', { name })}
          onClick={(e) => {
            e.stopPropagation()
            onInsert(name)
          }}
          className={action}
        >
          <TextCursorInput className="size-3" />
        </button>
      )}
    </span>
  )
}

'use client'

// Schema/table/column explorer for the editor's left rail (BigQuery-style).
// Schemas and tables are collapsible; `pii`-tagged columns are flagged loud
// (red dot), any other tag amber. Clicking a table opens its Schema + Data tab,
// while clicking a column inserts its identifier into the editor at the caret.
import { useMemo, useState } from 'react'
import { useTranslations } from 'next-intl'
import { ChevronRight, Database, KeyRound, Search, Table2 } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Input } from '@/components/ui/input'
import type { TreeColumn, TreeTable } from './catalog-schema'
import { usePersistedExpandedSchemas } from './use-persisted-expanded-schemas'

interface Props {
  datasourceId: number
  tables: TreeTable[]
  /** Insert a column identifier into the editor at the caret. */
  onInsert: (text: string) => void
  /** Open a table tab (Schema + Data preview). */
  onOpenTable: (table: TreeTable) => void
}

interface VisibleTable {
  table: TreeTable
  columns: TreeColumn[]
}

interface SchemaGroup {
  schema: string
  tables: VisibleTable[]
}

export function SchemaTree({ datasourceId, tables, onInsert, onOpenTable }: Props) {
  const t = useTranslations('Query')
  const [filter, setFilter] = useState('')
  const [expandedSchemas, setExpandedSchemas] = usePersistedExpandedSchemas(datasourceId)
  const filterActive = filter.trim().length > 0

  const groups = useMemo(() => {
    const q = filter.trim().toLowerCase()
    const bySchema = new Map<string, SchemaGroup>()

    for (const table of tables) {
      let columns = table.columns
      if (q) {
        const schemaMatches = table.schema.toLowerCase().includes(q)
        const tableMatches =
          table.name.toLowerCase().includes(q) || table.qualified.toLowerCase().includes(q)
        if (!schemaMatches && !tableMatches) {
          columns = table.columns.filter((column) => column.name.toLowerCase().includes(q))
          if (columns.length === 0) continue
        }
      }

      let group = bySchema.get(table.schema)
      if (!group) {
        group = { schema: table.schema, tables: [] }
        bySchema.set(table.schema, group)
      }
      group.tables.push({ table, columns })
    }

    return [...bySchema.values()]
  }, [tables, filter])

  const toggleSchema = (schema: string) => {
    const expanded = expandedSchemas[schema] !== false
    setExpandedSchemas({ ...expandedSchemas, [schema]: !expanded })
  }

  return (
    <div data-testid="schema-tree" className="flex min-h-0 flex-1 flex-col">
      <div className="relative px-2 pb-2">
        <Search className="text-muted-foreground absolute top-1/2 left-4 size-3.5 -translate-y-1/2" />
        <Input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder={t('schema.filterPlaceholder')}
          className="h-7 pl-7 text-xs"
        />
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto px-1 pb-2">
        {groups.length === 0 ? (
          <p className="text-muted-foreground px-3 py-2 text-xs">
            {t('schema.noMatch')}
          </p>
        ) : (
          groups.map((group) => (
            <SchemaGroupNode
              key={group.schema}
              group={group}
              expanded={filterActive || expandedSchemas[group.schema] !== false}
              forceTablesOpen={filterActive}
              onToggle={() => toggleSchema(group.schema)}
              onInsert={onInsert}
              onOpenTable={onOpenTable}
            />
          ))
        )}
      </div>
    </div>
  )
}

function SchemaGroupNode({
  group,
  expanded,
  forceTablesOpen,
  onToggle,
  onInsert,
  onOpenTable,
}: {
  group: SchemaGroup
  expanded: boolean
  forceTablesOpen: boolean
  onToggle: () => void
  onInsert: (text: string) => void
  onOpenTable: (table: TreeTable) => void
}) {
  const t = useTranslations('Query')
  return (
    <div data-testid="schema-group" data-schema={group.schema}>
      <div className="hover:bg-accent flex items-center gap-1 rounded-md pr-1.5 pl-1">
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={expanded}
          aria-label={
            expanded
              ? t('schema.collapseSchema', { schema: group.schema })
              : t('schema.expandSchema', { schema: group.schema })
          }
          className="text-muted-foreground flex size-5 shrink-0 items-center justify-center"
        >
          <ChevronRight className={cn('size-3.5 transition-transform', expanded && 'rotate-90')} />
        </button>
        <Database className="text-muted-foreground size-3.5 shrink-0" />
        <span
          title={t('schema.schemaTitle', { schema: group.schema })}
          className="min-w-0 flex-1 truncate py-1 font-mono text-xs font-medium"
        >
          {group.schema}
        </span>
      </div>
      {expanded && (
        <div className="ml-[14px] border-l pl-2">
          {group.tables.map(({ table, columns }) => (
            <TableNode
              key={table.qualified}
              table={table}
              columns={columns}
              onInsert={onInsert}
              onOpenTable={onOpenTable}
              forceOpen={forceTablesOpen}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function TableNode({
  table,
  columns,
  onInsert,
  onOpenTable,
  forceOpen,
}: {
  table: TreeTable
  columns: TreeColumn[]
  onInsert: (text: string) => void
  onOpenTable: (table: TreeTable) => void
  forceOpen: boolean
}) {
  const t = useTranslations('Query')
  const [locallyOpen, setLocallyOpen] = useState(false)
  const open = forceOpen || locallyOpen

  return (
    <div
      data-testid="schema-table"
      data-schema={table.schema}
      data-table={table.name}
    >
      <div className="hover:bg-accent group flex items-center gap-1 rounded-md pr-1.5 pl-1">
        <button
          type="button"
          onClick={() => setLocallyOpen((expanded) => !expanded)}
          aria-expanded={open}
          aria-label={
            open
              ? t('schema.collapseTable', { table: table.qualified })
              : t('schema.expandTable', { table: table.qualified })
          }
          className="text-muted-foreground flex size-5 shrink-0 items-center justify-center"
        >
          <ChevronRight className={cn('size-3.5 transition-transform', open && 'rotate-90')} />
        </button>
        <Table2 className="text-muted-foreground size-3.5 shrink-0" />
        <button
          type="button"
          onClick={() => onOpenTable(table)}
          title={t('schema.openTableTitle', { table: table.qualified })}
          className="min-w-0 flex-1 truncate py-1 text-left font-mono text-xs"
        >
          {table.name}
        </button>
        {table.piiCount > 0 && (
          <span className="shrink-0 rounded border border-red-500/25 bg-red-500/10 px-1 py-px font-mono text-[10px] text-red-500">
            {t('schema.piiBadge', { count: table.piiCount })}
          </span>
        )}
      </div>
      {open && (
        <div className="ml-[14px] border-l pl-2">
          {columns.map((column) => (
            <ColumnRow key={column.name} column={column} onInsert={onInsert} />
          ))}
        </div>
      )}
    </div>
  )
}

function ColumnRow({ column, onInsert }: { column: TreeColumn; onInsert: (text: string) => void }) {
  const t = useTranslations('Query')
  // Any tag makes a column classified; `pii` keeps the louder icon as the common case.
  const pii = column.tags.includes('pii')
  const sensitive = column.tags.length > 0
  return (
    <button
      type="button"
      onClick={() => onInsert(column.name)}
      title={
        t('schema.insertColumnTitle', { name: column.name, type: column.dataType }) +
        (column.nullable ? '' : t('schema.notNullSuffix'))
      }
      className="hover:bg-accent flex w-full items-center gap-1.5 rounded-md px-1.5 py-1 text-left"
    >
      {pii ? (
        <KeyRound className="size-3 shrink-0 text-red-500" />
      ) : (
        <span
          className={cn(
            'size-1.5 shrink-0 rounded-full',
            sensitive ? 'bg-amber-500' : 'bg-muted-foreground/30',
          )}
        />
      )}
      <span className={cn('truncate font-mono text-xs', pii && 'text-red-500')}>{column.name}</span>
      <span className="text-muted-foreground/70 ml-auto shrink-0 truncate font-mono text-[10px] lowercase">
        {column.dataType}
      </span>
    </button>
  )
}

'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { mutate } from 'swr';
import { createWorkloadBinding, updateWorkloadBinding } from '@/lib/api/client';
import { swrKeys } from '@/lib/hooks';
import type {
  WorkloadBinding,
  WorkloadBindingInput,
  WorkloadIssuer,
  WorkloadIssuerKind,
  WorkloadPurpose,
} from '@/lib/api/types';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { formatConditions, parseConditions } from './conditions';

export const MCP_SCOPES = [
  'mcp:read',
  'mcp:query',
  'mcp:approvals:write',
  'mcp:datasources:write',
  'mcp:identity:write',
  'mcp:policies:write',
  'mcp:tokens',
] as const;

const SUBJECT_EXAMPLES: Record<WorkloadIssuerKind, string> = {
  'aws-sts': 'arn:aws:iam::111122223333:role/service-role/batch-settlement',
  'github-actions': 'repo:acme/shop:environment:production',
  'hcp-terraform': 'organization:acme:project:data:workspace:pmon-policies:run_phase:apply',
  kubernetes: 'system:serviceaccount:batch:settlement',
  generic: 'service-account-id',
};

const CONDITION_EXAMPLES: Record<WorkloadIssuerKind, string> = {
  'aws-sts': 'principal_tags.kubernetes-namespace=batch',
  'github-actions': 'repository=acme/shop',
  'hcp-terraform': 'terraform_workspace_name=pmon-policies',
  kubernetes: 'kubernetes.io.namespace=batch',
  generic: 'claim=value',
};

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: WorkloadBinding | null;
  issuers: WorkloadIssuer[];
}

export function BindingFormDialog({ open, onOpenChange, editing, issuers }: Props) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl">
        {open && (
          <BindingForm
            key={editing ? `edit-${editing.id}` : 'create'}
            editing={editing}
            issuers={issuers}
            onClose={() => onOpenChange(false)}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

function BindingForm({
  editing,
  issuers,
  onClose,
}: {
  editing: WorkloadBinding | null;
  issuers: WorkloadIssuer[];
  onClose: () => void;
}) {
  const t = useTranslations('WorkloadBindings');
  const [name, setName] = useState(editing?.name ?? '');
  const [description, setDescription] = useState(editing?.description ?? '');
  const [issuer, setIssuer] = useState<string | null>(editing?.issuer ?? issuers[0]?.name ?? null);
  const [subject, setSubject] = useState(editing?.subject ?? '');
  const [conditions, setConditions] = useState(formatConditions(editing?.conditions ?? {}));
  const [principal, setPrincipal] = useState(editing?.principal ?? '');
  const [purposes, setPurposes] = useState<WorkloadPurpose[]>(editing?.purposes ?? ['wire']);
  const [scopes, setScopes] = useState<string[]>(editing?.mcpScopes ?? []);
  const [ttl, setTtl] = useState(String(editing?.ttlSeconds ?? 900));
  const [enabled, setEnabled] = useState(editing?.enabled ?? true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const kind = issuers.find((i) => i.name === issuer)?.kind ?? 'generic';
  const parsedConditions = parseConditions(conditions);
  const mcp = purposes.includes('mcp');
  const valid =
    name.trim() !== '' &&
    issuer != null &&
    subject.trim() !== '' &&
    purposes.length > 0 &&
    (!mcp || scopes.length > 0) &&
    parsedConditions != null;

  const togglePurpose = (purpose: WorkloadPurpose, on: boolean) =>
    setPurposes((prev) => (on ? [...prev.filter((p) => p !== purpose), purpose] : prev.filter((p) => p !== purpose)));
  const toggleScope = (scope: string, on: boolean) =>
    setScopes((prev) => (on ? [...prev.filter((s) => s !== scope), scope] : prev.filter((s) => s !== scope)));

  const handleSubmit = async () => {
    if (!valid || parsedConditions == null || issuer == null) return;
    setSaving(true);
    setError(null);
    const input: WorkloadBindingInput = {
      name: name.trim(),
      description: description.trim() || null,
      issuer,
      subject: subject.trim(),
      conditions: parsedConditions,
      principal: principal.trim() || null,
      purposes,
      mcpScopes: mcp ? scopes : [],
      ttlSeconds: Number(ttl),
      enabled,
    };
    try {
      if (editing) {
        await updateWorkloadBinding(editing.id, input);
        toast.success(t('form.toastUpdated', { name: input.name }));
      } else {
        await createWorkloadBinding(input);
        toast.success(t('form.toastCreated', { name: input.name }));
      }
      await mutate(swrKeys.workloadBindings);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('form.saveFailed'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <DialogHeader>
        <DialogTitle>{editing ? t('form.editTitle', { name: editing.name }) : t('form.addTitle')}</DialogTitle>
        <DialogDescription>{editing ? t('form.editDescription') : t('form.addDescription')}</DialogDescription>
      </DialogHeader>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">{error}</div>
      )}

      <div className="max-h-[65vh] space-y-3 overflow-y-auto py-1 pr-1">
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="binding-name">{t('form.labelName')}</Label>
            <Input
              id="binding-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="batch-settlement"
              disabled={editing != null}
              autoFocus={editing == null}
              required
            />
            <p className="text-muted-foreground text-xs">{t('form.nameHint')}</p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="binding-issuer">{t('form.labelIssuer')}</Label>
            <Select value={issuer} onValueChange={(v: string | null) => setIssuer(v)}>
              <SelectTrigger id="binding-issuer" className="w-full">
                <SelectValue placeholder={t('form.selectIssuer')}>
                  {(v: string | null) => {
                    const found = issuers.find((i) => i.name === v);
                    return found ? `${found.name} (${t(`kind.${found.kind}`)})` : v;
                  }}
                </SelectValue>
              </SelectTrigger>
              <SelectContent>
                {issuers.map((i) => (
                  <SelectItem key={i.name} value={i.name}>
                    {i.name} ({t(`kind.${i.kind}`)})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="binding-description">{t('form.labelDescription')}</Label>
          <Input id="binding-description" value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="binding-subject">{t('form.labelSubject')}</Label>
          <Input
            id="binding-subject"
            className="font-mono text-xs"
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            placeholder={SUBJECT_EXAMPLES[kind]}
            required
          />
          <p className="text-muted-foreground text-xs">
            {t('form.subjectHint')} {t('form.subjectExample', { example: SUBJECT_EXAMPLES[kind] })}
          </p>
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="binding-conditions">{t('form.labelConditions')}</Label>
          <Textarea
            id="binding-conditions"
            className="font-mono text-xs"
            rows={3}
            value={conditions}
            onChange={(e) => setConditions(e.target.value)}
            placeholder={CONDITION_EXAMPLES[kind]}
            aria-invalid={parsedConditions == null}
          />
          <p className="text-muted-foreground text-xs">
            {t('form.conditionsHint')} {t('form.conditionsExample', { example: CONDITION_EXAMPLES[kind] })}
          </p>
          {parsedConditions == null && <p className="text-xs text-red-500">{t('form.invalidConditions')}</p>}
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="binding-principal">{t('form.labelPrincipal')}</Label>
            <Input
              id="binding-principal"
              className="font-mono text-xs"
              value={principal}
              onChange={(e) => setPrincipal(e.target.value)}
              placeholder={`svc:${name.trim() || 'batch-settlement'}`}
            />
            <p className="text-muted-foreground text-xs">{t('form.principalHint')}</p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="binding-ttl">{t('form.labelTtl')}</Label>
            <Input
              id="binding-ttl"
              type="number"
              min={60}
              max={3600}
              value={ttl}
              onChange={(e) => setTtl(e.target.value)}
            />
            <p className="text-muted-foreground text-xs">{t('form.ttlHint')}</p>
          </div>
        </div>

        <fieldset className="space-y-2 rounded-lg border px-3 py-2">
          <legend className="px-1 text-sm font-medium">{t('form.labelPurposes')}</legend>
          {(['wire', 'mcp'] as const).map((purpose) => (
            <div key={purpose} className="flex items-center justify-between gap-3">
              <Label htmlFor={`binding-purpose-${purpose}`} className="font-normal">
                {purpose === 'wire' ? t('form.purposeWire') : t('form.purposeMcp')}
              </Label>
              <Switch
                id={`binding-purpose-${purpose}`}
                checked={purposes.includes(purpose)}
                onCheckedChange={(on: boolean) => togglePurpose(purpose, on)}
              />
            </div>
          ))}
        </fieldset>

        {mcp && (
          <fieldset className="space-y-2 rounded-lg border px-3 py-2">
            <legend className="px-1 text-sm font-medium">{t('form.labelScopes')}</legend>
            <p className="text-muted-foreground text-xs">{t('form.scopesHint')}</p>
            <div className="grid gap-2 sm:grid-cols-2">
              {MCP_SCOPES.map((scope) => (
                <div key={scope} className="flex items-center justify-between gap-2">
                  <Label htmlFor={`binding-scope-${scope}`} className="font-mono text-xs font-normal">
                    {scope}
                  </Label>
                  <Switch
                    id={`binding-scope-${scope}`}
                    checked={scopes.includes(scope)}
                    onCheckedChange={(on: boolean) => toggleScope(scope, on)}
                  />
                </div>
              ))}
            </div>
          </fieldset>
        )}

        <div className="flex items-center justify-between rounded-lg border px-3 py-2">
          <div className="space-y-0.5">
            <Label htmlFor="binding-enabled">{t('form.labelEnabled')}</Label>
            <p className="text-muted-foreground text-xs">{t('form.enabledHint')}</p>
          </div>
          <Switch id="binding-enabled" checked={enabled} onCheckedChange={setEnabled} />
        </div>
      </div>

      <DialogFooter>
        <Button variant="outline" onClick={onClose} disabled={saving}>
          {t('form.cancel')}
        </Button>
        <Button onClick={handleSubmit} disabled={!valid || saving}>
          {saving && <Loader2 className="size-3.5 animate-spin" />}
          {editing ? t('form.submitEdit') : t('form.submitCreate')}
        </Button>
      </DialogFooter>
    </>
  );
}

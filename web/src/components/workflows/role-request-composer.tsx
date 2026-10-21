'use client';

import { useState, type FormEvent } from 'react';
import { useTranslations } from 'next-intl';
import { mutate } from 'swr';
import { toast } from 'sonner';
import { createAccessRequest } from '@/lib/api/client';
import type { AccessRequest, AccessRequestInput } from '@/lib/api/types';
import { swrKeys, useRoles } from '@/lib/hooks';
import { DatasourceSelect } from '@/components/datasource-select';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';

const DURATION_OPTIONS: { value: string; key: string }[] = [
  { value: '1800', key: 'm30' },
  { value: '3600', key: 'h1' },
  { value: '7200', key: 'h2' },
  { value: '14400', key: 'h4' },
  { value: '28800', key: 'h8' },
  { value: '43200', key: 'h12' },
];

export function RoleRequestComposer({
  onCreated,
  onCancel,
}: {
  onCreated: (request: AccessRequest) => void;
  onCancel: () => void;
}) {
  const t = useTranslations('Workflows');
  const durations = DURATION_OPTIONS.map((duration) => ({
    value: duration.value,
    label: t(`durations.${duration.key}`),
  }));
  const { data: roles, isLoading: rolesLoading } = useRoles();
  const [roleId, setRoleId] = useState<string | null>(null);
  const [datasourceId, setDatasourceId] = useState<number | null>(null);
  const [reason, setReason] = useState('');
  const [durationSec, setDurationSec] = useState('3600');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedRoleId =
    roleId != null && roles?.some((role) => String(role.id) === roleId)
      ? roleId
      : roles && roles.length > 0
        ? String(roles[0].id)
        : null;
  const valid = selectedRoleId != null && reason.trim().length > 0;
  const roleName = roles?.find((role) => String(role.id) === selectedRoleId)?.name ?? t('roleComposer.selectRole');
  const durationLabel = durations.find((duration) => duration.value === durationSec)?.label ?? t('durations.h1');

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!valid || selectedRoleId == null) return;

    setBusy(true);
    setError(null);
    const input: AccessRequestInput = {
      roleId: Number(selectedRoleId),
      datasourceId,
      reason: reason.trim(),
      requestedDurationSec: Number(durationSec),
    };

    try {
      const created = await createAccessRequest(input);
      const upsertCreated = (requests: AccessRequest[] | undefined) => [
        created,
        ...(requests ?? []).filter((request) => request.id !== created.id),
      ];
      toast.success(t('roleComposer.submittedToast'));
      void mutate(swrKeys.accessRequests('PENDING'), upsertCreated, { revalidate: true });
      void mutate(swrKeys.accessRequests(undefined), upsertCreated, { revalidate: true });
      onCreated(created);
    } catch (submissionError) {
      setError(submissionError instanceof Error ? submissionError.message : t('roleComposer.submitFailed'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form data-workflow-composer-kind="ROLE" onSubmit={handleSubmit}>
      <Card>
        <CardHeader>
          <CardTitle>{t('roleComposer.title')}</CardTitle>
          <CardDescription>{t('roleComposer.description')}</CardDescription>
        </CardHeader>

        <CardContent className="space-y-4">
          {error && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
              {error}
            </div>
          )}

          <div className="space-y-1.5">
            <Label htmlFor="role-request-role">{t('fields.role')}</Label>
            <Select
              value={selectedRoleId}
              onValueChange={(value: string | null) => setRoleId(value)}
              disabled={rolesLoading}
            >
              <SelectTrigger id="role-request-role" className="w-full">
                <SelectValue placeholder={t('roleComposer.selectRole')}>{roleName}</SelectValue>
              </SelectTrigger>
              <SelectContent>
                {(roles ?? []).map((role) => (
                  <SelectItem key={role.id} value={String(role.id)}>
                    {role.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="role-request-datasource">{t('fields.datasourceOptional')}</Label>
            <DatasourceSelect
              id="role-request-datasource"
              value={datasourceId}
              onChange={setDatasourceId}
              allowAll
              allLabel={t('values.anyDatasource')}
              size="default"
              className="w-full"
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="role-request-reason">{t('fields.reason')}</Label>
            <Textarea
              id="role-request-reason"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder={t('roleComposer.reasonPlaceholder')}
              rows={3}
              required
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="role-request-duration">{t('fields.requestedDuration')}</Label>
            <Select value={durationSec} onValueChange={(value: string | null) => setDurationSec(value ?? '3600')}>
              <SelectTrigger id="role-request-duration" className="w-full">
                <SelectValue>{durationLabel}</SelectValue>
              </SelectTrigger>
              <SelectContent>
                {durations.map((duration) => (
                  <SelectItem key={duration.value} value={duration.value}>
                    {duration.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>

        <CardFooter className="justify-end gap-2">
          <Button type="button" variant="outline" onClick={onCancel} disabled={busy}>
            {t('actions.cancel')}
          </Button>
          <Button type="submit" disabled={!valid || busy}>
            {busy ? t('actions.submitting') : t('actions.submitRequest')}
          </Button>
        </CardFooter>
      </Card>
    </form>
  );
}

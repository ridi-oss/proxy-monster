"use client";

import type { ReactNode } from "react";
import { useTranslations } from "next-intl";
import type { AccessRequest } from "@/lib/api/types";

export function Field({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="space-y-1">
      <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">
        {label}
      </p>
      <div className="text-sm">{children}</div>
    </div>
  );
}

type Translator = ReturnType<typeof useTranslations>;

export function originLabel(
  request: AccessRequest,
  t: Translator,
): string | null {
  if (request.source === "mcp") return t("values.sourceMcp");
  if (request.source !== "github") return null;
  const ref = request.pullRequest;
  return ref
    ? `${t("values.sourceGithub")} ${ref.repository}#${ref.pr}`
    : t("values.sourceGithub");
}

function GithubSource({ request }: { request: AccessRequest }) {
  const t = useTranslations("Workflows");
  const ref = request.pullRequest;
  const text = originLabel(request, t);
  return (
    <div data-testid="request-origin" className="space-y-0.5">
      {ref?.prUrl ? (
        <a
          href={ref.prUrl}
          target="_blank"
          rel="noreferrer"
          className="font-mono underline"
        >
          {text}
        </a>
      ) : (
        <span className="font-mono">{text}</span>
      )}
      {ref?.path && (
        <div>
          <code className="font-mono">{ref.path}</code>
        </div>
      )}
    </div>
  );
}

export function RequestOrigin({ request }: { request: AccessRequest }) {
  const t = useTranslations("Workflows");
  return (
    <>
      {request.source === "github" && (
        <Field label={t("fields.source")}>
          <GithubSource request={request} />
        </Field>
      )}
      {request.source === "mcp" && (
        <Field label={t("fields.source")}>
          <span data-testid="request-origin">{originLabel(request, t)}</span>
        </Field>
      )}
      {request.scope && (
        <Field label={t("fields.scope")}>
          <code className="font-mono">{request.scope}</code>
        </Field>
      )}
    </>
  );
}

export function RunsAs({ request }: { request: AccessRequest }) {
  const t = useTranslations("Workflows");
  if (request.kind !== "QUERY") return null;
  return (
    <Field label={t("fields.runsAs")}>
      <code data-testid="request-runs-as" className="font-mono">
        {request.executeAs.length > 0 ? request.executeAs.join(", ") : "—"}
      </code>
    </Field>
  );
}

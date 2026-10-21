"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { Bot, Check, Copy, MonitorDown, Terminal, XCircle } from "lucide-react";
import type { McpConnectInfo } from "@/lib/api/types";
import { Button } from "@/components/ui/button";

function CopyBlock({ value }: { value: string }) {
  const t = useTranslations("Connect");
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-start gap-2">
      <pre className="bg-muted flex-1 overflow-x-auto rounded px-3 py-2 font-mono text-xs whitespace-pre-wrap">
        {value}
      </pre>
      <Button
        variant="outline"
        size="sm"
        aria-label={t("copy")}
        onClick={() => {
          void navigator.clipboard.writeText(value);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1500);
        }}
      >
        {copied ? (
          <Check className="size-3.5" />
        ) : (
          <Copy className="size-3.5" />
        )}
        {copied ? t("copied") : t("copy")}
      </Button>
    </div>
  );
}

function Section({
  icon,
  title,
  body,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  body: string;
  children?: React.ReactNode;
}) {
  return (
    <section className="space-y-3 rounded-lg border p-4">
      <div className="space-y-1">
        <h2 className="flex items-center gap-2 text-sm font-semibold">
          {icon}
          {title}
        </h2>
        <p className="text-muted-foreground text-sm">{body}</p>
      </div>
      {children}
    </section>
  );
}

// The current macOS installer; each pmon release replaces it on the rolling desktop-feed release.
const DESKTOP_DOWNLOAD =
  "https://github.com/ridi-oss/proxy-monster/releases/download/desktop-feed/ProxyMonsterDesktop.pkg";

/** The pmon://connect link Proxy Monster Desktop handles: it confirms, adds the server, and signs in. */
export function desktopConnectLink(info: McpConnectInfo): string {
  const params = new URLSearchParams({
    name: info.instanceName,
    url: info.mcpUrl.replace(/\/mcp$/, ""),
  });
  return `pmon://connect?${params.toString()}`;
}

/** Install instructions for this instance's MCP server, to paste to an agent. */
export function ConnectAgent({ info }: { info: McpConnectInfo }) {
  const t = useTranslations("Connect");
  const values = { installName: info.installName, mcpUrl: info.mcpUrl };
  const agentText = [
    t("agent.intro", values),
    `1. ${t("agent.step1", values)}`,
    `2. ${t("agent.step2", values)}`,
    t("agent.after"),
  ].join("\n");
  const pmonValues = {
    installName: info.installName,
    instance: info.instanceName,
    origin: info.mcpUrl.replace(/\/mcp$/, ""),
  };
  const pmonText = [
    t("pmon.intro", pmonValues),
    `1. ${t("pmon.step1", pmonValues)}`,
    `2. ${t("pmon.step2", pmonValues)}`,
    t("agent.after"),
  ].join("\n");

  return (
    <div className="space-y-4">
      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-muted-foreground">{t("instance")}</dt>
        <dd>
          <span className="font-mono">{info.instanceName}</span>
          {info.instanceDescription && (
            <span className="text-muted-foreground">
              {" "}
              — {info.instanceDescription}
            </span>
          )}
        </dd>
        <dt className="text-muted-foreground">{t("installName")}</dt>
        <dd className="font-mono">{info.installName}</dd>
        <dt className="text-muted-foreground">{t("url")}</dt>
        <dd className="font-mono break-all">{info.mcpUrl}</dd>
      </dl>
      <Section
        icon={<MonitorDown className="size-4" />}
        title={t("desktop.title")}
        body={t("desktop.body", { instance: info.instanceName })}
      >
        <div className="flex flex-wrap items-center gap-3">
          <Button asChild size="sm">
            <a href={desktopConnectLink(info)}>{t("desktop.open")}</a>
          </Button>
          <span className="text-muted-foreground text-xs">
            {t("desktop.notInstalled")}{" "}
            <a className="underline" href={DESKTOP_DOWNLOAD}>
              {t("desktop.download")}
            </a>
          </span>
        </div>
      </Section>
      <Section
        icon={<Bot className="size-4" />}
        title={t("agent.title")}
        body={t("agent.body")}
      >
        <CopyBlock value={agentText} />
      </Section>
      <Section
        icon={<Terminal className="text-muted-foreground size-4" />}
        title={t("pmon.title")}
        body={t("pmon.body")}
      >
        <CopyBlock value={pmonText} />
      </Section>
      <Section
        icon={<XCircle className="text-muted-foreground size-4" />}
        title={t("unsupported.title")}
        body={t("unsupported.body")}
      />
    </div>
  );
}

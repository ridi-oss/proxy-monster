import { renderToStaticMarkup } from "react-dom/server";
import { NextIntlClientProvider } from "next-intl";
import { expect, it } from "vitest";
import en from "../../../messages/en/connect.json";
import { ConnectAgent, desktopConnectLink } from "./connect-agent";

const info = {
  instanceName: "hr-pmon",
  instanceDescription: "HR and payroll data",
  mcpUrl: "https://hr-pmon.example.com/mcp",
  installName: "pmon-hr-pmon",
};

function render(): string {
  return renderToStaticMarkup(
    <NextIntlClientProvider locale="en" messages={{ Connect: en }}>
      <ConnectAgent info={info} />
    </NextIntlClientProvider>,
  );
}

it("renders the paste-to-agent block first from the API values", () => {
  const html = render();
  expect(html).toContain("Paste this to your agent");
  expect(html).toContain(
    "named pmon-hr-pmon with the URL https://hr-pmon.example.com/mcp",
  );
  expect(html).toContain("/mcp, pick pmon-hr-pmon, and choose Authenticate");
  expect(html.indexOf("Paste this to your agent")).toBeLessThan(
    html.indexOf("Already use pmon?"),
  );
  expect(html).not.toContain("claude mcp add");
  expect(html).not.toContain("codex mcp add");
});

it("offers the pmon login as a second block, the only path for Claude Desktop", () => {
  const html = render();
  const pmon = html.slice(
    html.indexOf("Already use pmon?"),
    html.indexOf("Not supported"),
  );
  expect(pmon).toContain(
    "stdio MCP server named pmon-hr-pmon that runs the command `pmon mcp hr-pmon`",
  );
  expect(pmon).toContain("`pmon login hr-pmon`");
  expect(pmon).toContain(
    "`pmon server set hr-pmon --url https://hr-pmon.example.com`",
  );
  expect(pmon).toContain("Claude Desktop");
  const unsupported = html.slice(html.indexOf("Not supported"));
  expect(unsupported).toContain("claude.ai and ChatGPT");
  expect(unsupported).toContain("Claude Desktop works through pmon");
});

it("shows the description on the page but leaves it out of the pasted text", () => {
  const html = render();
  const pasted = html.slice(html.indexOf("<pre"), html.indexOf("</pre>"));
  expect(html).toContain("HR and payroll data");
  expect(pasted).toContain("pmon-hr-pmon");
  expect(pasted).not.toContain("HR and payroll data");
});

it("puts no credential in any block", () => {
  expect(render()).not.toMatch(/bearer|token=|password=|--header|-H /i);
});

it("leads with Proxy Monster Desktop, whose button opens the connect link", () => {
  const html = render();
  expect(html.indexOf("Proxy Monster Desktop")).toBeLessThan(
    html.indexOf("Paste this to your agent"),
  );
  expect(html).toContain(
    'href="pmon://connect?name=hr-pmon&amp;url=https%3A%2F%2Fhr-pmon.example.com"',
  );
});

it("builds the connect link from the instance name and the server origin", () => {
  const link = new URL(desktopConnectLink(info));
  expect(link.protocol).toBe("pmon:");
  expect(link.host).toBe("connect");
  expect(link.searchParams.get("name")).toBe("hr-pmon");
  expect(link.searchParams.get("url")).toBe("https://hr-pmon.example.com");
});

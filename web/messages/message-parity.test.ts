import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Key-set parity between the locale trees: every namespace file present in one locale must exist in
// the other, and every dot-path leaf key in a namespace must exist in both locales' copy of it. This
// closes the gap left by src/lib/i18n/errors.ts, which only fails the build when ko/errors.json is
// MISSING an en key — extra ko keys and every non-errors namespace go unchecked there.

const messagesDir = path.dirname(fileURLToPath(import.meta.url));
const locales = ["en", "ko"] as const;

type Locale = (typeof locales)[number];

function collectKeys(value: unknown, prefix = ""): string[] {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return [prefix];
  }
  return Object.entries(value as Record<string, unknown>).flatMap(
    ([key, child]) => collectKeys(child, prefix ? `${prefix}.${key}` : key),
  );
}

function namespaceFiles(locale: Locale): string[] {
  return readdirSync(path.join(messagesDir, locale))
    .filter((file) => file.endsWith(".json"))
    .sort();
}

function readNamespace(locale: Locale, file: string): unknown {
  return JSON.parse(readFileSync(path.join(messagesDir, locale, file), "utf8"));
}

describe("message parity", () => {
  it("has the same namespace files in every locale", () => {
    expect(namespaceFiles("ko")).toEqual(namespaceFiles("en"));
  });

  for (const file of namespaceFiles("en")) {
    it(`${file} has the same keys in every locale`, () => {
      const enKeys = new Set(collectKeys(readNamespace("en", file)));
      const koKeys = new Set(collectKeys(readNamespace("ko", file)));
      expect({
        missingInKo: [...enKeys].filter((key) => !koKeys.has(key)).sort(),
        missingInEn: [...koKeys].filter((key) => !enKeys.has(key)).sort(),
      }).toEqual({ missingInKo: [], missingInEn: [] });
    });
  }
});

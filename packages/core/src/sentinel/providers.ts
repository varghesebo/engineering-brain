import { accessSync, constants, statSync } from "node:fs";
import { delimiter, join } from "node:path";
import { EngbrainError } from "../errors.js";

/**
 * Provider-neutral agent adapters, as DATA. This build detects which agent CLIs are installed (by looking for the executable on PATH; nothing is run, nothing is called) and states each one's
 * capabilities and data-boundary honestly. It does not launch any agent: `launchProvider` always refuses. A hosted model is never required.
 */
export interface ProviderInfo {
  id: "claude-code" | "codex" | "local-model";
  installed: boolean;
  executable: string | null;
  /** True when using it sends repository content to a third party over the network. */
  hosted: boolean;
  networkBoundary: string;
  rateLimits: string;
  tokenAccounting: string;
  note: string;
}

const EXECUTABLES: Record<ProviderInfo["id"], string[]> = { "claude-code": ["claude"], codex: ["codex"], "local-model": ["ollama", "llama-cli"] };
const BOUNDARY: Record<ProviderInfo["id"], { hosted: boolean; networkBoundary: string }> = {
  "claude-code": { hosted: true, networkBoundary: "sends the prompts and any files the agent reads to the provider's hosted service over the network" },
  codex: { hosted: true, networkBoundary: "sends the prompts and any files the agent reads to the provider's hosted service over the network" },
  "local-model": { hosted: false, networkBoundary: "runs on this machine; nothing leaves it unless the local server is configured otherwise (not verified here)" }
};

function findOnPath(names: string[], pathEnv: string | undefined): string | null {
  for (const dir of (pathEnv ?? "").split(delimiter).filter((d) => d !== "")) {
    for (const name of names) {
      const full = join(dir, name);
      try {
        if (statSync(full).isFile()) {
          accessSync(full, constants.X_OK);
          return full;
        }
      } catch {
        // not here
      }
    }
  }
  return null;
}

export function detectProviders(pathEnv: string | undefined = process.env["PATH"]): ProviderInfo[] {
  return (Object.keys(EXECUTABLES) as Array<ProviderInfo["id"]>).map((id) => {
    const executable = findOnPath(EXECUTABLES[id], pathEnv);
    return {
      id, installed: executable !== null, executable, ...BOUNDARY[id],
      rateLimits: "unknown: not queried (no call is made)", tokenAccounting: "only the provider can report it, and only after a call; none is made by this build",
      note: executable === null ? "not installed: it cannot be used and no reviewer can claim it" : "installed, but this build never launches it"
    };
  });
}

export function launchProvider(): never {
  throw new EngbrainError("POLICY_REFUSED", "this build does not launch any agent or model: edits are made by an agent you run yourself, inside an authorized worktree, and are then checked here");
}

export interface ReviewerIndependence { independent: boolean; reasons: string[] }
/**
 * Two role labels are not independence. A review counts as independently sourced only when the reviewer ran on a different provider than the builder AND was given different inputs (a different
 * input digest). Anything else is reported as NOT independent, with the reason, so it cannot be mistaken for a second opinion.
 */
export function reviewerIndependence(builder: { provider: string | null; inputDigest: string | null }, reviewer: { provider: string | null; inputDigest: string | null }, installed: readonly string[]): ReviewerIndependence {
  const reasons: string[] = [];
  if (reviewer.provider === null || builder.provider === null) {
    reasons.push("the provider of the builder or the reviewer is unknown");
  } else if (reviewer.provider === builder.provider) {
    reasons.push(`the reviewer and the builder are the same provider (${reviewer.provider}): the labels differ, the source does not`);
  } else if (!installed.includes(reviewer.provider)) {
    reasons.push(`the reviewer's provider (${reviewer.provider}) is not installed here: its independence cannot be claimed`);
  }
  if (reviewer.inputDigest === null || builder.inputDigest === null || reviewer.inputDigest === builder.inputDigest) {
    reasons.push("the reviewer was not given distinct inputs");
  }
  return { independent: reasons.length === 0, reasons };
}

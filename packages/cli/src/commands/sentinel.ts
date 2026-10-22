import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import {
  assuranceReport, buildManifest, decide, unsupportedTechniques, addFinding, createTaskHandoff, enforceWorktree, recordIteration, resumeFromHandoff, startRepair, addTraceLink, authorizeWorktree, checkWorktree, detectProviders, launchProvider, listFindings, resolveFinding, approveTask, authenticate, authorizeExecution, planVerification, probeCapabilities, recordFromImport, refuseRunIfUnenforceable, traceabilityReport, cancelTask, changedPathsSince, checkFreshness, createTask, getTask, issueCapability, listTasks, PROFILES, recordScopeCheck, repositoryFingerprint, requiredChecks, revalidateTask, ROLES,
  Store, taskReport, type Profile, type Role
} from "@engbrain/core";
import type { CliContext } from "../context.js";
import { EXIT, printable, printJsonOrText, type Io } from "../output.js";

export interface SentinelOptions { positionals: string[]; title: string | undefined; scope: string[]; profile: string | undefined; dryRun: boolean; reason: string | undefined; failOnStale: boolean; role: string | undefined; principal: string | undefined; minutes: number | undefined; runs: number | undefined; path: string | undefined; resolve: string | undefined; disposition: string | undefined; declared: string[]; severity: string | undefined; repro: string | undefined; evidenceSeq: number | undefined; evidenceCheck: string | undefined; evidenceFile: string | undefined; evidenceLine: number | undefined; sha: string | undefined; key: string | undefined; tokens: number | undefined; cost: number | undefined; elapsed: number | undefined; failure: string | undefined; maxIterations: number | undefined; handoffId: string | undefined; check: string | undefined; importId: string | undefined; requirement: number | undefined; behavior: string | undefined; test: string | undefined; testName: string | undefined; run: boolean; explain: boolean }

const usage = (io: Io, message: string): number => {
  io.stderr(`error: ${message}\n`);
  return EXIT.usage;
};

/**
 * `engbrain sentinel`: task planning and reporting. It never writes source code and never runs repository code. Anything that changes a task needs an authenticated operator (the real
 * identity from the operator store, never a name typed on the command line).
 */
export async function sentinelCommand(io: Io, context: CliContext, json: boolean, o: SentinelOptions): Promise<number> {
  const sub = o.positionals[0];
  /** Acts that bind to the source tree need a HASH-VERIFIED index (every file re-read), not the cheap heuristic: the fingerprint must describe the files as they are. */
  const bindsSource = (sub === "plan" && !o.dryRun) || ["approve", "authorize", "check-scope", "revalidate", "import"].includes(sub ?? "") || (sub === "verify" && o.run) || (sub === "worktree" && o.positionals[1] === "authorize");
  const writes = bindsSource || ["cancel", "capability"].includes(sub ?? "") || (sub === "review" && (o.resolve !== undefined || o.positionals[1] === "add")) || sub === "repair" || sub === "task-handoff" || sub === "manifest" || sub === "decide" || (sub === "worktree" && o.positionals[1] === "check" && io.env["ENGBRAIN_SENTINEL_CAPABILITY"] !== undefined) || (sub === "trace" && o.positionals[1] === "add");
  const open = { root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId };
  const store = writes ? await Store.open(open) : await Store.openReadOnly(open);
  try {
    const db = store.db;
    if (bindsSource) {
      const fresh = await checkFreshness(store, context.git, context.hardenedGit, { verify: true });
      if (fresh.level !== "hash_verified") {
        io.stderr(`error: the index is ${fresh.level}, not hash-verified: run \`engbrain refresh\` first (a task is bound to the source as it is on disk)\n`);
        return EXIT.refused;
      }
    } else if (!["cancel", "capability", "providers", "run", "adapters"].includes(sub ?? "")) {
      const fresh = await checkFreshness(store, context.git, context.hardenedGit, { verify: false });
      if (fresh.level === "stale" || fresh.level === "unknown") {
        io.stderr(`warning: the index is ${fresh.level}: reports describe the last published generation\n`);
      }
    }
    const fingerprint = ["cancel", "capability", "providers", "run", "adapters"].includes(sub ?? "") ? "" : repositoryFingerprint(db);
    switch (sub) {
      case "plan": {
        const profile = (o.profile ?? "A1") as Profile;
        if (o.title === undefined || o.scope.length === 0 || !PROFILES.includes(profile)) {
          return usage(io, "sentinel plan needs --title <text>, at least one --scope <path> and --profile A1|A2|A3|A4");
        }
        const checks = requiredChecks(store.dir, profile, o.scope);
        if (o.dryRun) {
          printJsonOrText(io, json, { dryRun: true, profile, scope: o.scope, requiredChecks: checks, sourceFingerprint: fingerprint },
            `dry run (nothing written, no source touched)\nprofile ${profile} (an internal profile, not a certification)\nrequired checks: ${checks.join(", ")}`);
          return EXIT.ok;
        }
        const actor = authenticate(store.dir, io.env);
        const base = (db.prepare("SELECT processed_oid AS oid FROM history_checkpoints WHERE ref_key = 'HEAD'").get() as { oid: string | null } | undefined)?.oid ?? undefined;
        const task = createTask(db, store.dir, { title: o.title, requester: actor, profile, scope: o.scope, sourceFingerprint: fingerprint, ...(base === undefined ? {} : { baseRevision: base }), worktreeId: createHash("sha256").update(realpathSync(context.root)).digest("hex").slice(0, 12) });
        printJsonOrText(io, json, { id: task.task_id, state: task.state, requiredChecks: checks }, `task ${task.task_id} created (CREATED); required checks: ${checks.join(", ")}`);
        return EXIT.ok;
      }
      case "approve": {
        const id = o.positionals[1];
        if (id === undefined) {
          return usage(io, "sentinel approve needs a task id");
        }
        const r = approveTask(db, store.dir, id, authenticate(store.dir, io.env), fingerprint);
        printJsonOrText(io, json, { result: r }, `approval recorded: ${r.approvalsValid}/${r.approvalsNeeded} valid; task is ${r.state} (this grants no permission to execute or release)`);
        return EXIT.ok;
      }
      case "authorize": {
        const id = o.positionals[1];
        if (id === undefined) {
          return usage(io, "sentinel authorize needs a task id");
        }
        const authId = authorizeExecution(db, store.dir, id, authenticate(store.dir, io.env), fingerprint, { ...(o.minutes === undefined ? {} : { ttlMinutes: o.minutes }), ...(o.runs === undefined ? {} : { maxRuns: o.runs }) });
        printJsonOrText(io, json, { authorization: authId }, `execution authorization ${authId} recorded (bound to the current source and policy; it is not approval, and it only allows the built-in synthetic worker in this build)`);
        return EXIT.ok;
      }
      case "revalidate": {
        const id = o.positionals[1];
        if (id === undefined) {
          return usage(io, "sentinel revalidate needs a task id");
        }
        const r = revalidateTask(db, store.dir, id, fingerprint);
        printJsonOrText(io, json, { result: r }, r.stale ? `authorization was stale (${r.reasons.map(printable).join("; ")}); the task is now ${r.state}` : `still current (${r.state})`);
        return EXIT.ok;
      }
      case "check-scope": {
        const id = o.positionals[1];
        const token = io.env["ENGBRAIN_SENTINEL_CAPABILITY"];
        if (id === undefined || token === undefined) {
          return usage(io, "sentinel check-scope needs a task id and a verification_worker capability in ENGBRAIN_SENTINEL_CAPABILITY");
        }
        const task = getTask(db, id);
        if (task.base_revision === null) {
          io.stderr("error: the task has no base revision to compare against\n");
          return EXIT.refused;
        }
        const changed = changedPathsSince(db, task.base_revision);
        if (changed.truncated || changed.relation !== "ancestor") {
          io.stderr(`error: the changes since the base cannot be listed completely (${changed.relation}${changed.truncated ? ", truncated" : ""}); the scope check refuses to guess\n`);
          return EXIT.refused;
        }
        const r = recordScopeCheck(db, store.dir, id, changed.paths, { capability: token }, fingerprint);
        printJsonOrText(io, json, { result: r, changedFiles: changed.paths.length, note: "committed changes only: uncommitted edits are not covered" }, `scope check ${r.outcome}${r.violations.length > 0 ? `; outside scope: ${r.violations.slice(0, 10).map(printable).join(", ")}` : ""} (committed changes since the base only)`);
        return r.outcome === "passed" ? EXIT.ok : EXIT.error;
      }
      case "verify": {
        const id = o.positionals[1];
        if (id === undefined || (!o.dryRun && !o.run && !o.explain)) {
          return usage(io, "sentinel verify <id> needs --dry-run, --explain or --run");
        }
        const sandbox = (await probeCapabilities()).result;
        if (o.run) {
          authenticate(store.dir, io.env);
          refuseRunIfUnenforceable(sandbox);
        }
        const plan = planVerification(db, store.dir, id, fingerprint, sandbox);
        const lines = [
          `${plan.taskId}  ${plan.state}`, ...plan.campaigns.map((c) => `${c.passClass.padEnd(17)} ${c.status}${c.checks.length === 0 ? "" : `  (${c.checks.map((k) => `${k.checkId}=${k.state === "current" ? k.outcome : k.state}`).join(", ")})`}`),
          ...(plan.selection === null ? [] : [`tests selected: ${plan.selection.selected.length}; unmapped files: ${plan.selection.unmapped.length}; policy sample: ${plan.selection.sample.length}`]),
          ...(o.explain ? plan.explanation.map((e) => `- ${printable(e)}`) : []), "no repository code was run (only the sandbox self-test, a fixed probe, executed)"
        ];
        printJsonOrText(io, json, { plan }, lines.join("\n"));
        return EXIT.ok;
      }
      case "import": {
        const id = o.positionals[1];
        const token = io.env["ENGBRAIN_SENTINEL_CAPABILITY"];
        if (id === undefined || o.check === undefined || o.importId === undefined || token === undefined) {
          return usage(io, "sentinel import <task id> --check-id <check id> --import <evidence import id> needs a verification capability in ENGBRAIN_SENTINEL_CAPABILITY");
        }
        const verdict = recordFromImport(db, store.dir, id, o.check, o.importId, { capability: token }, fingerprint);
        printJsonOrText(io, json, { verdict }, `recorded ${o.check} as ${verdict.outcome}${verdict.reasons.length > 0 ? ` (${verdict.reasons.map(printable).join("; ")})` : ""}`);
        return verdict.outcome === "passed" ? EXIT.ok : EXIT.error;
      }
      case "trace": {
        const id = o.positionals[o.positionals[1] === "add" ? 2 : 1];
        if (id === undefined) {
          return usage(io, "sentinel trace <id> | trace add <id> --requirement <n> --behavior <text> --test <path> [--test-name <t>] --check-id <check id>");
        }
        if (o.positionals[1] === "add") {
          if (o.requirement === undefined || o.behavior === undefined || o.test === undefined || o.check === undefined) {
            return usage(io, "trace add needs --requirement, --behavior, --test and --check-id");
          }
          const actor = authenticate(store.dir, io.env);
          addTraceLink(db, id, { requirementIx: o.requirement, behavior: o.behavior, testPath: o.test, checkId: o.check, ...(o.testName === undefined ? {} : { testName: o.testName }) }, actor.id);
          io.stdout("trace link recorded\n");
          return EXIT.ok;
        }
        const report = traceabilityReport(db, store.dir, id, fingerprint);
        printJsonOrText(io, json, { report }, [...report.requirements.map((r) => `requirement ${r.index} [${r.status}] ${printable(r.text)}${r.links.map((l) => `\n    ${printable(l.behavior)} -> ${printable(l.testPath)}${l.testName === null ? "" : `#${printable(l.testName)}`} (${l.checkId}: ${l.result})`).join("")}`), `missing coverage: ${report.missingCoverage.length}`].join("\n"));
        return EXIT.ok;
      }
      case "providers": {
        const providers = detectProviders(io.env["PATH"]);
        printJsonOrText(io, json, { providers }, providers.map((p) => `${p.id.padEnd(12)} ${p.installed ? "installed" : "not installed"}  ${p.hosted ? "HOSTED (content leaves this machine)" : "local"}  ${printable(p.note)}`).join("\n") + "\nthis build never launches an agent or calls a model");
        return EXIT.ok;
      }
      case "run": {
        const id = o.positionals[1];
        if (id === undefined || o.scope.length === 0) {
          return usage(io, "sentinel run <id> --scope <path> ... names the explicit scope; this build prepares and checks, it never launches an agent");
        }
        try {
          launchProvider();
        } catch (error) {
          io.stderr(`error: ${error instanceof Error ? error.message : "refused"}\nnext steps: authorize a throwaway worktree (sentinel worktree authorize ${id} --path <dir>), run your own agent in it, then \`sentinel worktree check ${id}\` and import its test results\n`);
        }
        return EXIT.refused;
      }
      case "worktree": {
        const action = o.positionals[1];
        const id = o.positionals[2];
        if ((action !== "authorize" && action !== "check") || id === undefined) {
          return usage(io, "sentinel worktree authorize <id> --path <dir> | worktree check <id>");
        }
        if (action === "authorize") {
          if (o.path === undefined) {
            return usage(io, "worktree authorize needs --path <throwaway worktree directory>");
          }
          const r = authorizeWorktree(db, id, authenticate(store.dir, io.env), o.path, context.root);
          printJsonOrText(io, json, { files: r.files }, `worktree authorized (${r.files} files recorded as the baseline); changes outside the task scope, to existing tests or policy, or not declared will be flagged`);
          return EXIT.ok;
        }
        const token = io.env["ENGBRAIN_SENTINEL_CAPABILITY"];
        const declared = o.declared.length > 0 ? o.declared : undefined;
        // with a verification capability the check is ENFORCED: scope evidence is recorded, a protected change opens a blocking finding, an undeclared change pauses the task
        const report = token === undefined ? checkWorktree(db, id, declared) : enforceWorktree(db, store.dir, id, { capability: token }, fingerprint, declared);
        printJsonOrText(io, json, { report }, [`added ${report.added.length}, modified ${report.modified.length}, deleted ${report.deleted.length}`, ...report.unauthorized.map((p) => `UNAUTHORIZED ${printable(p)}`), ...report.protectedChanges.map((p) => `PROTECTED (test/policy) ${printable(p)}`), report.ok ? "ok" : "NOT ok"].join("\n"));
        return report.ok ? EXIT.ok : EXIT.error;
      }
      case "adapters": {
        const gaps = unsupportedTechniques(db, process.platform);
        printJsonOrText(io, json, { platform: process.platform, notAvailable: gaps }, [`platform ${process.platform}: techniques without an available adapter (they can never pass):`, ...gaps.map((g) => `  ${g.technique.padEnd(16)} ${g.state}${g.reason === "" ? "" : `  (${printable(g.reason)})`}`)].join("\n"));
        return EXIT.ok;
      }
      case "manifest": {
        const id = o.positionals[1];
        if (id === undefined) {
          return usage(io, "sentinel manifest <id>");
        }
        const m = buildManifest(db, store.dir, id, authenticate(store.dir, io.env), fingerprint, {});
        printJsonOrText(io, json, { manifest: { id: m.manifest_id, sha256: m.body_sha256 } }, `manifest ${m.manifest_id} (sha256 ${m.body_sha256}) recorded for the current source; it goes stale on any source, policy or evidence change`);
        return EXIT.ok;
      }
      case "decide": {
        const id = o.positionals[1];
        if (id === undefined) {
          return usage(io, "sentinel decide <id>");
        }
        const d = decide(db, store.dir, id, fingerprint, {});
        printJsonOrText(io, json, { decision: d }, [`${d.outcome}`, ...d.reasons.map((r) => `  - ${printable(r)}`), ...d.unmeasured.map((u) => `  unmeasured: ${printable(u)}`), d.note].join("\n"));
        return d.outcome === "ELIGIBLE_FOR_APPROVAL" ? EXIT.ok : EXIT.error;
      }
      case "assurance-report": {
        const id = o.positionals[1];
        if (id === undefined) {
          return usage(io, "sentinel assurance-report <id>");
        }
        const r = assuranceReport(db, store.dir, id, fingerprint, {});
        printJsonOrText(io, json, { report: r.json }, r.text);
        return EXIT.ok;
      }
      case "repair": {
        const action = o.positionals[1];
        const id = o.positionals[2];
        if ((action !== "start" && action !== "record") || id === undefined) {
          return usage(io, "sentinel repair start <id> [--max-iterations n] | repair record <id> --key <k> --tokens n --cost n --elapsed ms --failure <signature>");
        }
        if (action === "start") {
          const state = startRepair(db, id, authenticate(store.dir, io.env), o.maxIterations === undefined ? {} : { maxIterations: o.maxIterations });
          printJsonOrText(io, json, { state }, `repair loop started: at most ${state.budget.maxIterations} iterations, ${state.budget.maxSameFailure} repeats of one failure`);
          return EXIT.ok;
        }
        if (o.key === undefined || o.failure === undefined) {
          return usage(io, "repair record needs --key and --failure (and usage numbers)");
        }
        const token = io.env["ENGBRAIN_SENTINEL_CAPABILITY"];
        const who = token !== undefined ? { capability: token } : { operator: authenticate(store.dir, io.env) };
        const r = recordIteration(db, store.dir, id, who, { iterationKey: o.key, tokens: o.tokens ?? 0, costMicro: o.cost ?? 0, elapsedMs: o.elapsed ?? 0, failureSignature: o.failure });
        printJsonOrText(io, json, { result: r }, r.allowed ? `iteration ${r.state.iterations} recorded; wait ${r.backoffMs} ms before the next` : `STOPPED: ${printable(r.reason ?? "")} (the task is BLOCKED)`);
        return r.allowed ? EXIT.ok : EXIT.refused;
      }
      case "task-handoff": {
        const id = o.positionals[1];
        if (id === undefined) {
          return usage(io, "sentinel task-handoff <id>");
        }
        const handoff = createTaskHandoff(db, store.dir, id, authenticate(store.dir, io.env), fingerprint);
        printJsonOrText(io, json, { handoff }, `handoff ${handoff} written; resume with \`sentinel resume ${id} --handoff ${handoff}\``);
        return EXIT.ok;
      }
      case "resume": {
        const id = o.positionals[1];
        if (id === undefined || o.handoffId === undefined) {
          return usage(io, "sentinel resume <id> --handoff <handoff id>");
        }
        const view = resumeFromHandoff(db, store.dir, o.handoffId, id, fingerprint);
        printJsonOrText(io, json, { resume: view }, [`${view.taskId}  ${view.state}  revision ${view.revision}`, ...view.openFindings.map((f) => `open ${f.severity} finding: ${printable(f.title)}`), `pending checks: ${view.pendingChecks.join(", ") || "none"}`].join("\n"));
        return EXIT.ok;
      }
      case "review": {
        const id = o.positionals[1];
        if (id === undefined) {
          return usage(io, "sentinel review <id> [--resolve <finding id> --disposition fixed|rejected|accepted_risk --reason <text>]");
        }
        if (o.positionals[1] === "add") {
          const taskId = o.positionals[2];
          const token = io.env["ENGBRAIN_SENTINEL_CAPABILITY"];
          if (taskId === undefined || token === undefined || o.title === undefined || o.repro === undefined || (o.severity !== "blocking" && o.severity !== "advisory")) {
            return usage(io, "sentinel review add <id> --severity blocking|advisory --title <t> --repro <steps> (--evidence-seq n | --evidence-check c | --evidence-file p --evidence-line n --sha <sha256>) with a reviewer capability in ENGBRAIN_SENTINEL_CAPABILITY");
          }
          const evidence = o.evidenceSeq !== undefined ? { kind: "evidence" as const, seq: o.evidenceSeq } : o.evidenceCheck !== undefined ? { kind: "check" as const, checkId: o.evidenceCheck }
            : o.evidenceFile !== undefined && o.sha !== undefined && o.evidenceLine !== undefined ? { kind: "file" as const, path: o.evidenceFile, sha256: o.sha, line: o.evidenceLine } : null;
          if (evidence === null) {
            return usage(io, "a finding needs evidence: --evidence-seq, --evidence-check, or --evidence-file with --evidence-line and --sha");
          }
          const worktree = db.prepare("SELECT path FROM sentinel_worktrees WHERE task_id = ? AND status = 'active'").get(taskId) as { path: string } | undefined;
          const hashOf = (p: string): string | null => {
            if (worktree === undefined || p.startsWith("/") || p.split("/").includes("..")) {
              return null;
            }
            try {
              return createHash("sha256").update(readFileSync(join(worktree.path, p))).digest("hex");
            } catch {
              return null;
            }
          };
          const findingId = addFinding(db, store.dir, taskId, { severity: o.severity, title: o.title, evidence, reproduction: o.repro }, token, fingerprint, hashOf);
          printJsonOrText(io, json, { finding: findingId }, `finding ${findingId} recorded (its evidence was checked; a blocking finding withdraws approvals)`);
          return EXIT.ok;
        }
        if (o.resolve !== undefined) {
          if (o.disposition === undefined || o.reason === undefined || !["fixed", "rejected", "accepted_risk"].includes(o.disposition)) {
            return usage(io, "--resolve needs --disposition fixed|rejected|accepted_risk and --reason");
          }
          resolveFinding(db, id, o.resolve, o.disposition as "fixed" | "rejected" | "accepted_risk", authenticate(store.dir, io.env), o.reason);
          io.stdout("finding dispositioned\n");
          return EXIT.ok;
        }
        const findings = listFindings(db, id);
        printJsonOrText(io, json, { findings }, findings.map((f) => `${f.finding_id}  ${f.severity.padEnd(8)} ${f.disposition.padEnd(13)} ${printable(f.source_role)}/${printable(f.source_principal)}  ${printable(f.title)}`).join("\n") || "no findings");
        return EXIT.ok;
      }
      case "evidence": {
        const id = o.positionals[1];
        if (id === undefined) {
          return usage(io, "sentinel evidence <id>");
        }
        const report = taskReport(db, store.dir, id, fingerprint);
        printJsonOrText(io, json, { evidence: report.evidence }, report.evidence.map((e) => `#${e.seq} ${e.at} ${e.origin} ${printable(e.kind)} ${e.checkId ?? "-"} ${e.outcome} by ${printable(e.verifier)}`).join("\n") || "no evidence");
        return EXIT.ok;
      }
      case "capability": {
        const [, action, id] = o.positionals;
        if (action !== "issue" || id === undefined || o.role === undefined || o.principal === undefined || !(ROLES as readonly string[]).includes(o.role)) {
          return usage(io, `sentinel capability issue <task id> --role ${ROLES.join("|")} --principal <name> [--minutes n]`);
        }
        const task = getTask(db, id);
        const token = issueCapability(store.dir, { role: o.role as Role, taskId: id, principal: o.principal, ttlSeconds: (o.minutes ?? 60) * 60, issuer: authenticate(store.dir, io.env), epoch: task.cap_epoch });
        printJsonOrText(io, json, { token }, `capability for ${o.role} on ${id} as ${o.principal} (shown once; it is bound to this task and expires):\n${token}`);
        return EXIT.ok;
      }
      case "list": {
        const tasks = listTasks(db);
        printJsonOrText(io, json, { tasks }, tasks.map((t) => `${t.task_id}  ${t.state.padEnd(22)} ${t.profile}  ${printable(t.title)}`).join("\n") || "no tasks");
        return EXIT.ok;
      }
      case "status":
      case "report": {
        const id = o.positionals[1];
        if (id === undefined) {
          return usage(io, `sentinel ${sub} needs a task id`);
        }
        const report = taskReport(db, store.dir, id, fingerprint);
        const lines = [
          `${report.task.task_id}  ${report.task.state}  profile ${report.task.profile}  revision ${report.task.revision}`, `title: ${printable(report.task.title)}`, `scope: ${report.task.scope.map(printable).join(", ")}`,
          ...(report.task.blocked_reason === null ? [] : [`blocked: ${printable(report.task.blocked_reason)}`]),
          `required checks: ${report.eligibility.requiredChecks.join(", ")}`, ...report.eligibility.blockers.map((b) => `  blocker: ${printable(b)}`), ...report.eligibility.stale.map((b) => `  stale: ${printable(b)}`),
          `approvals: ${report.eligibility.approvalsValid}/${report.eligibility.approvalsNeeded} valid; authorization ${report.authorization.standing}`, `log integrity: ${report.chain.ok ? "ok" : `FAILED (${printable(report.chain.problems[0] ?? "")})`}`,
          ...report.evidence.map((e) => `  evidence #${e.seq} ${e.origin} ${printable(e.kind)} ${e.checkId ?? "-"} ${e.outcome} by ${printable(e.verifier)}`), report.note
        ];
        printJsonOrText(io, json, { report }, lines.join("\n"));
        return EXIT.ok;
      }
      case "cancel": {
        const id = o.positionals[1];
        if (id === undefined || o.reason === undefined) {
          return usage(io, "sentinel cancel needs a task id and --reason <text>");
        }
        const task = cancelTask(db, store.dir, id, authenticate(store.dir, io.env), o.reason);
        io.stdout(`task ${task.task_id} cancelled; queued work was dropped\n`);
        return EXIT.ok;
      }
      default:
        return usage(io, "sentinel needs: plan | list | status <id> | report <id> | approve <id> | authorize <id> | revalidate <id> | check-scope <id> | verify <id> --dry-run|--explain|--run | import <id> | trace <id> | providers | run <id> | worktree authorize|check <id> | review <id> | review add <id> | repair start|record <id> | task-handoff <id> | resume <id> | evidence <id> | adapters | manifest <id> | decide <id> | assurance-report <id> | capability issue <id> | cancel <id>");
    }
  } finally {
    store.close();
  }
}

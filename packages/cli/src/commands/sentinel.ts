import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import {
  addTraceLink, approveTask, authenticate, authorizeExecution, planVerification, probeCapabilities, recordFromImport, refuseRunIfUnenforceable, traceabilityReport, cancelTask, changedPathsSince, checkFreshness, createTask, getTask, issueCapability, listTasks, PROFILES, recordScopeCheck, repositoryFingerprint, requiredChecks, revalidateTask, ROLES,
  Store, taskReport, type Profile, type Role
} from "@engbrain/core";
import type { CliContext } from "../context.js";
import { EXIT, printable, printJsonOrText, type Io } from "../output.js";

export interface SentinelOptions { positionals: string[]; title: string | undefined; scope: string[]; profile: string | undefined; dryRun: boolean; reason: string | undefined; failOnStale: boolean; role: string | undefined; principal: string | undefined; minutes: number | undefined; runs: number | undefined; check: string | undefined; importId: string | undefined; requirement: number | undefined; behavior: string | undefined; test: string | undefined; testName: string | undefined; run: boolean; explain: boolean }

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
  const bindsSource = (sub === "plan" && !o.dryRun) || ["approve", "authorize", "check-scope", "revalidate", "import"].includes(sub ?? "") || (sub === "verify" && o.run);
  const writes = bindsSource || ["cancel", "capability"].includes(sub ?? "") || (sub === "trace" && o.positionals[1] === "add");
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
    } else if (sub !== "cancel" && sub !== "capability") {
      const fresh = await checkFreshness(store, context.git, context.hardenedGit, { verify: false });
      if (fresh.level === "stale" || fresh.level === "unknown") {
        io.stderr(`warning: the index is ${fresh.level}: reports describe the last published generation\n`);
      }
    }
    const fingerprint = sub === "cancel" || sub === "capability" ? "" : repositoryFingerprint(db);
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
        return usage(io, "sentinel needs: plan | list | status <id> | report <id> | approve <id> | authorize <id> | revalidate <id> | check-scope <id> | verify <id> --dry-run|--explain|--run | import <id> | trace <id> | capability issue <id> | cancel <id>");
    }
  } finally {
    store.close();
  }
}

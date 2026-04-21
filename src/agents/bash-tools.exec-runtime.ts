import fs from "node:fs/promises";
import path from "node:path";
import type { AgentToolResult } from "@mariozechner/pi-agent-core";
import {
  DEFAULT_EXEC_APPROVAL_TIMEOUT_MS,
  resolveExecApprovalAllowedDecisions,
  type ExecHost,
  type ExecApprovalDecision,
  type ExecTarget,
} from "../infra/exec-approvals.js";
import { requestHeartbeatNow } from "../infra/heartbeat-wake.js";
import { isDangerousHostInheritedEnvVarName } from "../infra/host-env-security.js";
import { findPathKey, mergePathPrepend } from "../infra/path-prepend.js";
import { enqueueSystemEvent } from "../infra/system-events.js";
import { scopedHeartbeatWakeOptions } from "../routing/session-key.js";
import type { ClosureKind, ProcessSession } from "./bash-process-registry.js";
import type { ExecToolDetails } from "./bash-tools.exec-types.js";
import type { BashSandboxConfig } from "./bash-tools.shared.js";
export { applyPathPrepend, findPathKey, normalizePathPrepend } from "../infra/path-prepend.js";
export {
  normalizeExecAsk,
  normalizeExecHost,
  normalizeExecSecurity,
  normalizeExecTarget,
} from "../infra/exec-approvals.js";
import { logWarn } from "../logger.js";
import type { ManagedRun } from "../process/supervisor/index.js";
import { getProcessSupervisor } from "../process/supervisor/index.js";
import type { RunExit, TerminationReason } from "../process/supervisor/types.js";
import { normalizeDeliveryContext, type DeliveryContext } from "../utils/delivery-context.js";
import {
  addSession,
  appendOutput,
  createSessionSlug,
  markExited,
  tail,
} from "./bash-process-registry.js";
import {
  buildDockerExecArgs,
  chunkString,
  clampWithDefault,
  readEnvInt,
} from "./bash-tools.shared.js";
import { buildCursorPositionResponse, stripDsrRequests } from "./pty-dsr.js";
import { getShellConfig, sanitizeBinaryOutput } from "./shell-utils.js";

export { execSchema } from "./bash-tools.schemas.js";

const SMKX = "\x1b[?1h";
const RMKX = "\x1b[?1l";

/**
 * Detect cursor key mode from PTY output chunk.
 * Uses lastIndexOf to find the *last* toggle in the chunk.
 * Returns "application" if smkx is the last toggle, "normal" if rmkx is last,
 * or null if no toggle is found.
 */
export function detectCursorKeyMode(raw: string): "application" | "normal" | null {
  const lastSmkx = raw.lastIndexOf(SMKX);
  const lastRmkx = raw.lastIndexOf(RMKX);
  if (lastSmkx === -1 && lastRmkx === -1) {
    return null;
  }
  // Whichever appears later in the chunk wins.
  return lastSmkx > lastRmkx ? "application" : "normal";
}

// Sanitize inherited host env before merge so dangerous variables from process.env
// are not propagated into non-sandboxed executions.
export function sanitizeHostBaseEnv(env: Record<string, string>): Record<string, string> {
  const sanitized: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    const upperKey = key.toUpperCase();
    if (upperKey === "PATH") {
      sanitized[key] = value;
      continue;
    }
    if (isDangerousHostInheritedEnvVarName(upperKey)) {
      continue;
    }
    sanitized[key] = value;
  }
  return sanitized;
}
// Centralized sanitization helper.
// Throws an error if dangerous variables or PATH modifications are detected on the host.
export function validateHostEnv(env: Record<string, string>): void {
  for (const key of Object.keys(env)) {
    const upperKey = key.toUpperCase();

    // 1. Block known dangerous variables (Fail Closed)
    if (isDangerousHostInheritedEnvVarName(upperKey)) {
      throw new Error(
        `Security Violation: Environment variable '${key}' is forbidden during host execution.`,
      );
    }

    // 2. Strictly block PATH modification on host
    // Allowing custom PATH on the gateway/node can lead to binary hijacking.
    if (upperKey === "PATH") {
      throw new Error(
        "Security Violation: Custom 'PATH' variable is forbidden during host execution.",
      );
    }
  }
}
export const DEFAULT_MAX_OUTPUT = clampWithDefault(
  readEnvInt("PI_BASH_MAX_OUTPUT_CHARS"),
  200_000,
  1_000,
  200_000,
);
export const DEFAULT_PENDING_MAX_OUTPUT = clampWithDefault(
  readEnvInt("OPENCLAW_BASH_PENDING_MAX_OUTPUT_CHARS"),
  30_000,
  1_000,
  200_000,
);
export const DEFAULT_PATH =
  process.env.PATH ?? "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
export const DEFAULT_NOTIFY_TAIL_CHARS = 400;
const DEFAULT_NOTIFY_SNIPPET_CHARS = 180;
export const DEFAULT_APPROVAL_TIMEOUT_MS = DEFAULT_EXEC_APPROVAL_TIMEOUT_MS;
export const DEFAULT_APPROVAL_REQUEST_TIMEOUT_MS = DEFAULT_APPROVAL_TIMEOUT_MS + 10_000;
const DEFAULT_APPROVAL_RUNNING_NOTICE_MS = 10_000;
const APPROVAL_SLUG_LENGTH = 8;

export type ExecProcessFailureKind =
  | "shell-command-not-found"
  | "shell-not-executable"
  | "overall-timeout"
  | "no-output-timeout"
  | "signal"
  | "aborted"
  | "runtime-error"
  | "artifact-missing"
  | "artifact-wrong-tree";

type ExecExitFailureKind = Exclude<
  ExecProcessFailureKind,
  "runtime-error" | "artifact-missing" | "artifact-wrong-tree"
>;

export type ExecProcessOutcome =
  | {
      status: "completed";
      exitCode: number;
      exitSignal: NodeJS.Signals | number | null;
      durationMs: number;
      aggregated: string;
      timedOut: false;
    }
  | {
      status: "failed";
      exitCode: number | null;
      exitSignal: NodeJS.Signals | number | null;
      durationMs: number;
      aggregated: string;
      timedOut: boolean;
      failureKind: ExecProcessFailureKind;
      reason: string;
    };

export type ExecProcessHandle = {
  session: ProcessSession;
  startedAt: number;
  pid?: number;
  promise: Promise<ExecProcessOutcome>;
  kill: () => void;
  /** Immediately suppress all future `onUpdate` calls for this handle. */
  disableUpdates: () => void;
};

export function renderExecHostLabel(host: ExecHost) {
  return host === "sandbox" ? "sandbox" : host === "gateway" ? "gateway" : "node";
}

export function renderExecTargetLabel(target: ExecTarget) {
  return target === "auto" ? "auto" : renderExecHostLabel(target);
}

export function isRequestedExecTargetAllowed(params: {
  configuredTarget: ExecTarget;
  requestedTarget: ExecTarget;
  sandboxAvailable?: boolean;
}) {
  if (params.requestedTarget === params.configuredTarget) {
    return true;
  }
  if (params.configuredTarget === "auto") {
    if (
      params.sandboxAvailable &&
      (params.requestedTarget === "gateway" || params.requestedTarget === "node")
    ) {
      return false;
    }
    return true;
  }
  return false;
}

export function resolveExecTarget(params: {
  configuredTarget?: ExecTarget;
  requestedTarget?: ExecTarget | null;
  elevatedRequested: boolean;
  sandboxAvailable: boolean;
}) {
  const configuredTarget = params.configuredTarget ?? "auto";
  const requestedTarget = params.requestedTarget ?? null;
  if (
    requestedTarget &&
    !isRequestedExecTargetAllowed({
      configuredTarget,
      requestedTarget,
      sandboxAvailable: params.sandboxAvailable,
    })
  ) {
    const allowedConfig = Array.from(
      new Set(
        configuredTarget === "auto" &&
          params.sandboxAvailable &&
          (requestedTarget === "gateway" || requestedTarget === "node")
          ? [renderExecTargetLabel(requestedTarget)]
          : requestedTarget === "gateway" && !params.sandboxAvailable
            ? ["gateway", "auto"]
            : [renderExecTargetLabel(requestedTarget), "auto"],
      ),
    ).join(" or ");
    throw new Error(
      `exec host not allowed (requested ${renderExecTargetLabel(requestedTarget)}; ` +
        `configured host is ${renderExecTargetLabel(configuredTarget)}; ` +
        `set tools.exec.host=${allowedConfig} to allow this override).`,
    );
  }
  const selectedTarget = requestedTarget ?? configuredTarget;
  const resolvedTarget = params.elevatedRequested
    ? selectedTarget === "node"
      ? "node"
      : "gateway"
    : selectedTarget;
  const effectiveHost =
    resolvedTarget === "auto" ? (params.sandboxAvailable ? "sandbox" : "gateway") : resolvedTarget;
  return {
    configuredTarget,
    requestedTarget,
    selectedTarget: resolvedTarget,
    effectiveHost,
  };
}

export function normalizeNotifyOutput(value: string) {
  return value.replace(/\s+/g, " ").trim();
}

function compactNotifyOutput(value: string, maxChars = DEFAULT_NOTIFY_SNIPPET_CHARS) {
  const normalized = normalizeNotifyOutput(value);
  if (!normalized) {
    return "";
  }
  if (normalized.length <= maxChars) {
    return normalized;
  }
  const safe = Math.max(1, maxChars - 1);
  return `${normalized.slice(0, safe)}…`;
}

export function applyShellPath(env: Record<string, string>, shellPath?: string | null) {
  if (!shellPath) {
    return;
  }
  const entries = shellPath
    .split(path.delimiter)
    .map((part) => part.trim())
    .filter(Boolean);
  if (entries.length === 0) {
    return;
  }
  const pathKey = findPathKey(env);
  const merged = mergePathPrepend(env[pathKey], entries);
  if (merged) {
    env[pathKey] = merged;
  }
}

function maybeNotifyOnExit(session: ProcessSession, status: "completed" | "failed") {
  if (!session.backgrounded || !session.notifyOnExit || session.exitNotified) {
    return;
  }
  const sessionKey = session.sessionKey?.trim();
  if (!sessionKey) {
    return;
  }
  session.exitNotified = true;
  const exitLabel = session.exitSignal
    ? `signal ${session.exitSignal}`
    : `code ${session.exitCode ?? 0}`;
  const output = compactNotifyOutput(
    tail(session.tail || session.aggregated || "", DEFAULT_NOTIFY_TAIL_CHARS),
  );
  if (status === "completed" && !output && session.notifyOnExitEmptySuccess !== true) {
    return;
  }
  const summary = output
    ? `Exec ${status} (${session.id.slice(0, 8)}, ${exitLabel}) :: ${output}`
    : `Exec ${status} (${session.id.slice(0, 8)}, ${exitLabel})`;
  enqueueSystemEvent(summary, {
    sessionKey,
    deliveryContext: session.notifyDeliveryContext,
    trusted: false,
  });
  requestHeartbeatNow(scopedHeartbeatWakeOptions(sessionKey, { reason: "exec-event" }));
}

export function createApprovalSlug(id: string) {
  return id.slice(0, APPROVAL_SLUG_LENGTH);
}

export function buildApprovalPendingMessage(params: {
  warningText?: string;
  approvalSlug: string;
  approvalId: string;
  allowedDecisions?: readonly ExecApprovalDecision[];
  command: string;
  cwd: string | undefined;
  host: "gateway" | "node";
  nodeId?: string;
}) {
  let fence = "```";
  while (params.command.includes(fence)) {
    fence += "`";
  }
  const commandBlock = `${fence}sh\n${params.command}\n${fence}`;
  const lines: string[] = [];
  const allowedDecisions = params.allowedDecisions ?? resolveExecApprovalAllowedDecisions();
  const decisionText = allowedDecisions.join("|");
  const warningText = params.warningText?.trim();
  if (warningText) {
    lines.push(warningText, "");
  }
  lines.push(`Approval required (id ${params.approvalSlug}, full ${params.approvalId}).`);
  lines.push(`Host: ${params.host}`);
  if (params.nodeId) {
    lines.push(`Node: ${params.nodeId}`);
  }
  lines.push(`CWD: ${params.cwd ?? "(node default)"}`);
  lines.push("Command:");
  lines.push(commandBlock);
  lines.push("Mode: foreground (interactive approvals available).");
  lines.push(
    allowedDecisions.includes("allow-always")
      ? "Background mode requires pre-approved policy (allow-always or ask=off)."
      : "Background mode requires an effective policy that allows pre-approval (for example ask=off).",
  );
  lines.push(`Reply with: /approve ${params.approvalSlug} ${decisionText}`);
  if (!allowedDecisions.includes("allow-always")) {
    lines.push(
      "The effective approval policy requires approval every time, so Allow Always is unavailable.",
    );
  }
  lines.push("If the short code is ambiguous, use the full id in /approve.");
  return lines.join("\n");
}

export function resolveApprovalRunningNoticeMs(value?: number) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return DEFAULT_APPROVAL_RUNNING_NOTICE_MS;
  }
  if (value <= 0) {
    return 0;
  }
  return Math.floor(value);
}

export function emitExecSystemEvent(
  text: string,
  opts: { sessionKey?: string; contextKey?: string; deliveryContext?: DeliveryContext },
) {
  const sessionKey = opts.sessionKey?.trim();
  if (!sessionKey) {
    return;
  }
  enqueueSystemEvent(text, {
    sessionKey,
    contextKey: opts.contextKey,
    deliveryContext: opts.deliveryContext,
  });
  requestHeartbeatNow(scopedHeartbeatWakeOptions(sessionKey, { reason: "exec-event" }));
}

function joinExecFailureOutput(aggregated: string, reason: string) {
  return aggregated ? `${aggregated}\n\n${reason}` : reason;
}

function classifyExecFailureKind(params: {
  exitReason: TerminationReason;
  exitCode: number;
  isShellFailure: boolean;
  exitSignal: NodeJS.Signals | number | null;
}): ExecExitFailureKind {
  if (params.isShellFailure) {
    return params.exitCode === 127 ? "shell-command-not-found" : "shell-not-executable";
  }
  if (params.exitReason === "overall-timeout") {
    return "overall-timeout";
  }
  if (params.exitReason === "no-output-timeout") {
    return "no-output-timeout";
  }
  if (params.exitSignal != null) {
    return "signal";
  }
  return "aborted";
}

export function formatExecFailureReason(params: {
  failureKind: ExecExitFailureKind;
  exitSignal: NodeJS.Signals | number | null;
  timeoutSec: number | null | undefined;
}): string {
  switch (params.failureKind) {
    case "shell-command-not-found":
      return "Command not found";
    case "shell-not-executable":
      return "Command not executable (permission denied)";
    case "overall-timeout":
      return typeof params.timeoutSec === "number" && params.timeoutSec > 0
        ? `Command timed out after ${params.timeoutSec} seconds. If this command is expected to take longer, re-run with a higher timeout (e.g., exec timeout=300). If it should keep running, start it with exec background=true or yieldMs so OpenClaw can register a pollable process session. Do not rely on shell backgrounding with a trailing &.`
        : "Command timed out. If this command is expected to take longer, re-run with a higher timeout (e.g., exec timeout=300). If it should keep running, start it with exec background=true or yieldMs so OpenClaw can register a pollable process session. Do not rely on shell backgrounding with a trailing &.";
    case "no-output-timeout":
      return "Command timed out waiting for output";
    case "signal":
      return `Command aborted by signal ${params.exitSignal}`;
    case "aborted":
      return "Command aborted before exit code was captured";
  }
  throw new Error("Unsupported exec failure kind");
}

export function buildExecExitOutcome(params: {
  exit: RunExit;
  aggregated: string;
  durationMs: number;
  timeoutSec: number | null | undefined;
}): ExecProcessOutcome {
  const exitCode = params.exit.exitCode ?? 0;
  const isNormalExit = params.exit.reason === "exit";
  const isShellFailure = exitCode === 126 || exitCode === 127;
  const status: ExecProcessOutcome["status"] =
    isNormalExit && !isShellFailure ? "completed" : "failed";
  if (status === "completed") {
    const exitMsg = exitCode !== 0 ? `\n\n(Command exited with code ${exitCode})` : "";
    return {
      status: "completed",
      exitCode,
      exitSignal: params.exit.exitSignal,
      durationMs: params.durationMs,
      aggregated: params.aggregated + exitMsg,
      timedOut: false,
    };
  }
  const failureKind = classifyExecFailureKind({
    exitReason: params.exit.reason,
    exitCode,
    isShellFailure,
    exitSignal: params.exit.exitSignal,
  });
  const reason = formatExecFailureReason({
    failureKind,
    exitSignal: params.exit.exitSignal,
    timeoutSec: params.timeoutSec,
  });
  return {
    status: "failed",
    exitCode: params.exit.exitCode,
    exitSignal: params.exit.exitSignal,
    durationMs: params.durationMs,
    aggregated: params.aggregated,
    timedOut: params.exit.timedOut,
    failureKind,
    reason: joinExecFailureOutput(params.aggregated, reason),
  };
}

export function buildExecRuntimeErrorOutcome(params: {
  error: unknown;
  aggregated: string;
  durationMs: number;
}): ExecProcessOutcome {
  return {
    status: "failed",
    exitCode: null,
    exitSignal: null,
    durationMs: params.durationMs,
    aggregated: params.aggregated,
    timedOut: false,
    failureKind: "runtime-error",
    reason: joinExecFailureOutput(params.aggregated, String(params.error)),
  };
}

/**
 * Opt-in post-exit artifact gate for workflow-aware exec callers.
 *
 * When present on {@link runExecProcess} options, the runtime verifies that
 * every path in `requiredArtifacts` exists under `workspaceRoot` *after* the
 * child process exits and *before* the session is marked completed. If any
 * required artifact is absent, the run is downgraded from lifecycle-only
 * success to a workflow failure, and wrong-tree materialization (the same
 * relative path resolved under any of `wrongTreeRoots`) is reported
 * separately so callers can distinguish "nothing produced" from "produced
 * under the wrong workspace".
 *
 * Generic exec runs (callers that omit this field) retain their existing
 * lifecycle-only behavior.
 */
export type WorkflowArtifactContract = {
  /**
   * Required artifact paths. May be absolute or relative to `workspaceRoot`.
   * Each resolved path MUST live inside `workspaceRoot`; any path that
   * escapes is treated as a configuration error and fails verification.
   */
  requiredArtifacts: string[];
  /**
   * Optional sibling roots that should NOT contain the artifacts. When a
   * required artifact is missing under `workspaceRoot` but the same relative
   * path is present under any of these roots, the failure is classified as
   * `artifact-wrong-tree` instead of `artifact-missing`.
   */
  wrongTreeRoots?: string[];
  /** Absolute path that `requiredArtifacts` are resolved against. */
  workspaceRoot: string;
};

export type ArtifactVerificationResult =
  | { ok: true }
  | {
      ok: false;
      kind: "artifact-missing" | "artifact-wrong-tree";
      missing: string[];
      wrongTreeMatches: Array<{ expectedPath: string; foundAt: string }>;
    };

async function pathExists(target: string): Promise<boolean> {
  try {
    await fs.stat(target);
    return true;
  } catch {
    return false;
  }
}

function resolveWithinRoot(root: string, rel: string): string | null {
  const absRoot = path.resolve(root);
  const candidate = path.resolve(absRoot, rel);
  const normalizedRoot = absRoot.endsWith(path.sep) ? absRoot : `${absRoot}${path.sep}`;
  if (candidate !== absRoot && !candidate.startsWith(normalizedRoot)) {
    return null;
  }
  return candidate;
}

/**
 * Why: the exec caller needs to know not just "did something get written"
 * but "did the canonical workspace get the artifacts, or did the run write
 * into a sibling tree by mistake". We check the canonical location first;
 * if anything is missing there, and wrong-tree roots were supplied, we
 * probe those siblings for the same relative paths and surface them
 * explicitly so the caller can route recovery instead of retrying blind.
 */
export async function verifyWorkflowArtifacts(
  contract: WorkflowArtifactContract,
): Promise<ArtifactVerificationResult> {
  const workspaceRoot = path.resolve(contract.workspaceRoot);
  const normalizedRoot = workspaceRoot.endsWith(path.sep)
    ? workspaceRoot
    : `${workspaceRoot}${path.sep}`;
  const missing: string[] = [];
  // Missing artifacts whose relative path we will probe under wrong-tree
  // roots, so we can distinguish "never produced" from "produced in the
  // wrong workspace".
  const missingProbes: Array<{ expected: string; rel: string }> = [];

  for (const entry of contract.requiredArtifacts) {
    const resolved = path.isAbsolute(entry)
      ? path.resolve(entry)
      : resolveWithinRoot(workspaceRoot, entry);
    if (!resolved) {
      missing.push(path.resolve(workspaceRoot, entry));
      continue;
    }
    if (resolved !== workspaceRoot && !resolved.startsWith(normalizedRoot)) {
      // Resolved path escapes workspaceRoot; treat as missing rather than
      // silently accepting an out-of-tree path.
      missing.push(resolved);
      continue;
    }
    if (!(await pathExists(resolved))) {
      missing.push(resolved);
      missingProbes.push({ expected: resolved, rel: path.relative(workspaceRoot, resolved) });
    }
  }

  if (missing.length === 0) {
    return { ok: true };
  }

  const wrongTreeMatches: Array<{ expectedPath: string; foundAt: string }> = [];
  const wrongTreeRoots = contract.wrongTreeRoots ?? [];
  if (wrongTreeRoots.length > 0) {
    for (const probe of missingProbes) {
      for (const wrongRoot of wrongTreeRoots) {
        const absWrong = path.resolve(wrongRoot);
        if (absWrong === workspaceRoot) {
          continue;
        }
        const candidate = resolveWithinRoot(absWrong, probe.rel);
        if (!candidate) {
          continue;
        }
        if (await pathExists(candidate)) {
          wrongTreeMatches.push({ expectedPath: probe.expected, foundAt: candidate });
          break;
        }
      }
    }
  }

  return {
    ok: false,
    kind: wrongTreeMatches.length > 0 ? "artifact-wrong-tree" : "artifact-missing",
    missing,
    wrongTreeMatches,
  };
}

function formatArtifactFailureReason(
  verification: Extract<ArtifactVerificationResult, { ok: false }>,
): string {
  const lines: string[] = [];
  if (verification.kind === "artifact-wrong-tree") {
    lines.push(
      "Workflow artifact verification failed: required artifacts were produced in the wrong tree.",
    );
    for (const match of verification.wrongTreeMatches) {
      lines.push(`  expected: ${match.expectedPath}`);
      lines.push(`  found at: ${match.foundAt}`);
    }
    const pureMissing = verification.missing.filter(
      (m) => !verification.wrongTreeMatches.some((w) => w.expectedPath === m),
    );
    if (pureMissing.length > 0) {
      lines.push("Additional required artifacts were not produced anywhere:");
      for (const m of pureMissing) {
        lines.push(`  missing: ${m}`);
      }
    }
  } else {
    lines.push("Workflow artifact verification failed: required artifacts were not produced.");
    for (const m of verification.missing) {
      lines.push(`  missing: ${m}`);
    }
  }
  return lines.join("\n");
}

export function buildExecArtifactFailureOutcome(params: {
  verification: Extract<ArtifactVerificationResult, { ok: false }>;
  aggregated: string;
  durationMs: number;
  exitCode: number | null;
  exitSignal: NodeJS.Signals | number | null;
}): ExecProcessOutcome {
  const reason = formatArtifactFailureReason(params.verification);
  return {
    status: "failed",
    exitCode: params.exitCode,
    exitSignal: params.exitSignal,
    durationMs: params.durationMs,
    aggregated: params.aggregated,
    timedOut: false,
    failureKind: params.verification.kind,
    reason: joinExecFailureOutput(params.aggregated, reason),
  };
}

export async function runExecProcess(opts: {
  command: string;
  // Execute this instead of `command` (which is kept for display/session/logging).
  // Used to sanitize safeBins execution while preserving the original user input.
  execCommand?: string;
  workdir: string;
  env: Record<string, string>;
  sandbox?: BashSandboxConfig;
  containerWorkdir?: string | null;
  usePty: boolean;
  warnings: string[];
  maxOutput: number;
  pendingMaxOutput: number;
  notifyOnExit: boolean;
  notifyOnExitEmptySuccess?: boolean;
  scopeKey?: string;
  sessionKey?: string;
  notifyDeliveryContext?: DeliveryContext;
  timeoutSec: number | null;
  /**
   * Opt-in workflow artifact gate. When provided, the run is only reported
   * as completed if every entry in `requiredArtifacts` exists under
   * `workspaceRoot` after the process exits. Omitting this field preserves
   * legacy lifecycle-only behavior for generic exec callers.
   */
  workflowArtifacts?: WorkflowArtifactContract;
  onUpdate?: (partialResult: AgentToolResult<ExecToolDetails>) => void;
}): Promise<ExecProcessHandle> {
  const startedAt = Date.now();
  const sessionId = createSessionSlug();
  const execCommand = opts.execCommand ?? opts.command;
  const supervisor = getProcessSupervisor();
  const shellRuntimeEnv: Record<string, string> = {
    ...opts.env,
    OPENCLAW_SHELL: "exec",
  };

  const session: ProcessSession = {
    id: sessionId,
    command: opts.command,
    scopeKey: opts.scopeKey,
    sessionKey: opts.sessionKey,
    notifyDeliveryContext: normalizeDeliveryContext(opts.notifyDeliveryContext),
    notifyOnExit: opts.notifyOnExit,
    notifyOnExitEmptySuccess: opts.notifyOnExitEmptySuccess === true,
    exitNotified: false,
    child: undefined,
    stdin: undefined,
    pid: undefined,
    startedAt,
    cwd: opts.workdir,
    maxOutputChars: opts.maxOutput,
    pendingMaxOutputChars: opts.pendingMaxOutput,
    totalOutputChars: 0,
    pendingStdout: [],
    pendingStderr: [],
    pendingStdoutChars: 0,
    pendingStderrChars: 0,
    aggregated: "",
    tail: "",
    exited: false,
    exitCode: undefined as number | null | undefined,
    exitSignal: undefined as NodeJS.Signals | number | null | undefined,
    truncated: false,
    backgrounded: false,
    cursorKeyMode: opts.usePty ? "unknown" : "normal",
  };
  addSession(session);

  // Tracks whether the exec run's promise has settled (process exited or
  // spawn failed).  Once settled the agent-loop no longer expects
  // tool_execution_update events, so emitUpdate must become a no-op to
  // prevent calling into a disposed agent run (the "Agent listener invoked
  // outside active run" crash — see #62520).
  let updatesDisabled = false;

  const emitUpdate = () => {
    if (!opts.onUpdate) {
      return;
    }
    if (session.backgrounded || session.exited || updatesDisabled) {
      return;
    }
    const tailText = session.tail || session.aggregated;
    const warningText = opts.warnings.length ? `${opts.warnings.join("\n")}\n\n` : "";
    // Note: opts.onUpdate() is provided by pi-agent-core's agent-loop and
    // internally pushes Promise.resolve(emit(event)) into an updateEvents
    // array.  Because emit → processEvents is async, any failure (e.g.
    // activeRun cleared) produces a *rejected Promise*, not a synchronous
    // throw — so a try-catch here would be ineffective.  Instead we rely
    // on the `updatesDisabled` flag being set proactively: by the promise
    // chain on process exit (Layer 1) and by `disableUpdates()` on abort
    // signal (Layer 2) — both of which prevent this call from ever being
    // reached after the agent run has ended.
    opts.onUpdate({
      content: [{ type: "text", text: warningText + (tailText || "") }],
      details: {
        status: "running",
        sessionId,
        pid: session.pid ?? undefined,
        startedAt,
        cwd: session.cwd,
        tail: session.tail,
      },
    });
  };

  const handleStdout = (data: string) => {
    const raw = data;
    // Detect smkx/rmkx BEFORE sanitizeBinaryOutput strips ESC sequences.
    // Note: PTY chunking is arbitrary, but smkx/rmkx sequences are typically short (4-5 bytes)
    // and sent atomically by terminals. Split across chunks is rare in practice.
    const mode = detectCursorKeyMode(raw);
    if (mode) {
      session.cursorKeyMode = mode;
    }
    const str = sanitizeBinaryOutput(raw);
    for (const chunk of chunkString(str)) {
      appendOutput(session, "stdout", chunk);
      emitUpdate();
    }
  };

  const handleStderr = (data: string) => {
    const str = sanitizeBinaryOutput(data);
    for (const chunk of chunkString(str)) {
      appendOutput(session, "stderr", chunk);
      emitUpdate();
    }
  };

  const timeoutMs =
    typeof opts.timeoutSec === "number" && opts.timeoutSec > 0
      ? Math.floor(opts.timeoutSec * 1000)
      : undefined;
  let sandboxFinalizeToken: unknown;

  const spawnSpec:
    | {
        mode: "child";
        argv: string[];
        env: NodeJS.ProcessEnv;
        stdinMode: "pipe-open" | "pipe-closed";
      }
    | {
        mode: "pty";
        ptyCommand: string;
        childFallbackArgv: string[];
        env: NodeJS.ProcessEnv;
        stdinMode: "pipe-open";
      } = await (async () => {
    if (opts.sandbox) {
      const backendExecSpec = await opts.sandbox.buildExecSpec?.({
        command: execCommand,
        workdir: opts.containerWorkdir ?? opts.sandbox.containerWorkdir,
        env: shellRuntimeEnv,
        usePty: opts.usePty,
      });
      sandboxFinalizeToken = backendExecSpec?.finalizeToken;
      return {
        mode: "child" as const,
        argv: backendExecSpec?.argv ?? [
          "docker",
          ...buildDockerExecArgs({
            containerName: opts.sandbox.containerName,
            command: execCommand,
            workdir: opts.containerWorkdir ?? opts.sandbox.containerWorkdir,
            env: shellRuntimeEnv,
            tty: opts.usePty,
          }),
        ],
        env: backendExecSpec?.env ?? process.env,
        stdinMode:
          backendExecSpec?.stdinMode ??
          (opts.usePty ? ("pipe-open" as const) : ("pipe-closed" as const)),
      };
    }
    const { shell, args: shellArgs } = getShellConfig();
    const childArgv = [shell, ...shellArgs, execCommand];
    if (opts.usePty) {
      return {
        mode: "pty" as const,
        ptyCommand: execCommand,
        childFallbackArgv: childArgv,
        env: shellRuntimeEnv,
        stdinMode: "pipe-open" as const,
      };
    }
    return {
      mode: "child" as const,
      argv: childArgv,
      env: shellRuntimeEnv,
      stdinMode: "pipe-closed" as const,
    };
  })();

  let managedRun: ManagedRun | null = null;
  let usingPty = spawnSpec.mode === "pty";
  const cursorResponse = buildCursorPositionResponse();

  const onSupervisorStdout = (chunk: string) => {
    if (usingPty) {
      const { cleaned, requests } = stripDsrRequests(chunk);
      if (requests > 0 && managedRun?.stdin) {
        for (let i = 0; i < requests; i += 1) {
          managedRun.stdin.write(cursorResponse);
        }
      }
      handleStdout(cleaned);
      return;
    }
    handleStdout(chunk);
  };

  try {
    const spawnBase = {
      runId: sessionId,
      sessionId: opts.sessionKey?.trim() || sessionId,
      backendId: opts.sandbox ? "exec-sandbox" : "exec-host",
      scopeKey: opts.scopeKey,
      cwd: opts.workdir,
      env: spawnSpec.env,
      timeoutMs,
      captureOutput: false,
      onStdout: onSupervisorStdout,
      onStderr: handleStderr,
    };
    managedRun =
      spawnSpec.mode === "pty"
        ? await supervisor.spawn({
            ...spawnBase,
            mode: "pty",
            ptyCommand: spawnSpec.ptyCommand,
          })
        : await supervisor.spawn({
            ...spawnBase,
            mode: "child",
            argv: spawnSpec.argv,
            stdinMode: spawnSpec.stdinMode,
          });
  } catch (err) {
    if (spawnSpec.mode === "pty") {
      const warning = `Warning: PTY spawn failed (${String(err)}); retrying without PTY for \`${opts.command}\`.`;
      logWarn(
        `exec: PTY spawn failed (${String(err)}); retrying without PTY for "${opts.command}".`,
      );
      opts.warnings.push(warning);
      usingPty = false;
      try {
        managedRun = await supervisor.spawn({
          runId: sessionId,
          sessionId: opts.sessionKey?.trim() || sessionId,
          backendId: "exec-host",
          scopeKey: opts.scopeKey,
          mode: "child",
          argv: spawnSpec.childFallbackArgv,
          cwd: opts.workdir,
          env: spawnSpec.env,
          stdinMode: "pipe-open",
          timeoutMs,
          captureOutput: false,
          onStdout: handleStdout,
          onStderr: handleStderr,
        });
      } catch (retryErr) {
        markExited(
          session,
          null,
          null,
          "failed",
          opts.workflowArtifacts ? "lifecycle-only" : undefined,
        );
        maybeNotifyOnExit(session, "failed");
        throw retryErr;
      }
    } else {
      markExited(
        session,
        null,
        null,
        "failed",
        opts.workflowArtifacts ? "lifecycle-only" : undefined,
      );
      maybeNotifyOnExit(session, "failed");
      throw err;
    }
  }
  session.stdin = managedRun.stdin;
  session.pid = managedRun.pid;

  const promise = managedRun
    .wait()
    .then(async (exit): Promise<ExecProcessOutcome> => {
      // Disable updates *before* markExited so that any late stdout/stderr
      // data events queued in the same event-loop tick cannot sneak through
      // the `session.exited` guard before it flips to true.
      updatesDisabled = true;

      const durationMs = Date.now() - startedAt;
      let outcome = buildExecExitOutcome({
        exit,
        aggregated: session.aggregated.trim(),
        durationMs,
        timeoutSec: opts.timeoutSec,
      });

      // Workflow artifact gate: if the caller opted in and the process
      // completed at lifecycle, verify required artifacts exist under the
      // canonical workspace before persisting completion. Failed
      // verification downgrades the outcome *before* markExited so the
      // FinishedSession reflects truthful closure state.
      let closureKind: ClosureKind | undefined;
      if (opts.workflowArtifacts) {
        if (outcome.status === "completed") {
          const verification = await verifyWorkflowArtifacts(opts.workflowArtifacts);
          if (verification.ok) {
            closureKind = "artifact-verified";
          } else {
            outcome = buildExecArtifactFailureOutcome({
              verification,
              aggregated: session.aggregated.trim(),
              durationMs,
              exitCode: exit.exitCode ?? null,
              exitSignal: exit.exitSignal,
            });
            closureKind = verification.kind;
          }
        } else {
          // Process failed at lifecycle — workflow gate did not run, but
          // persist the distinction so downstream readers can tell this was
          // not an artifact-verified closure.
          closureKind = "lifecycle-only";
        }
      }

      markExited(session, exit.exitCode, exit.exitSignal, outcome.status, closureKind);
      maybeNotifyOnExit(session, outcome.status);
      if (!session.child && session.stdin) {
        session.stdin.destroyed = true;
      }
      if (opts.sandbox?.finalizeExec) {
        await opts.sandbox.finalizeExec({
          status: outcome.status,
          exitCode: exit.exitCode ?? null,
          timedOut: exit.timedOut,
          token: sandboxFinalizeToken,
        });
      }
      return outcome;
    })
    .catch((err): ExecProcessOutcome => {
      updatesDisabled = true;
      markExited(
        session,
        null,
        null,
        "failed",
        opts.workflowArtifacts ? "lifecycle-only" : undefined,
      );
      maybeNotifyOnExit(session, "failed");
      return buildExecRuntimeErrorOutcome({
        error: err,
        aggregated: session.aggregated.trim(),
        durationMs: Date.now() - startedAt,
      });
    });

  return {
    session,
    startedAt,
    pid: session.pid ?? undefined,
    promise,
    kill: () => {
      managedRun?.cancel("manual-cancel");
    },
    disableUpdates: () => {
      updatesDisabled = true;
    },
  };
}

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import {
  getFinishedSession,
  markBackgrounded,
  resetProcessRegistryForTests,
} from "./bash-process-registry.js";
import {
  runExecProcess,
  verifyWorkflowArtifacts,
  type WorkflowArtifactContract,
} from "./bash-tools.exec-runtime.js";

let workspaceRoot: string;
let wrongRoot: string;

function currentEnv(): Record<string, string> {
  return Object.fromEntries(
    Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] != null),
  );
}

async function runWithContract(params: {
  command: string;
  workflowArtifacts?: WorkflowArtifactContract;
}) {
  const handle = await runExecProcess({
    command: params.command,
    workdir: workspaceRoot,
    env: currentEnv(),
    usePty: false,
    warnings: [],
    maxOutput: 20_000,
    pendingMaxOutput: 20_000,
    notifyOnExit: false,
    timeoutSec: 10,
    workflowArtifacts: params.workflowArtifacts,
  });
  // Ensure the finished session is persisted so we can inspect closureKind.
  markBackgrounded(handle.session);
  const outcome = await handle.promise;
  const finished = getFinishedSession(handle.session.id);
  return { outcome, finished, sessionId: handle.session.id };
}

beforeEach(async () => {
  workspaceRoot = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-workflow-artifacts-"));
  wrongRoot = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-workflow-wrongtree-"));
});

afterEach(async () => {
  resetProcessRegistryForTests();
  await fs.rm(workspaceRoot, { recursive: true, force: true });
  await fs.rm(wrongRoot, { recursive: true, force: true });
});

describe("verifyWorkflowArtifacts", () => {
  test("returns ok when every required artifact exists under workspaceRoot", async () => {
    await fs.writeFile(path.join(workspaceRoot, "out.txt"), "done");
    const result = await verifyWorkflowArtifacts({
      requiredArtifacts: ["out.txt"],
      workspaceRoot,
    });
    expect(result).toEqual({ ok: true });
  });

  test("classifies pure absence as artifact-missing", async () => {
    const result = await verifyWorkflowArtifacts({
      requiredArtifacts: ["out.txt"],
      workspaceRoot,
    });
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.kind).toBe("artifact-missing");
    expect(result.missing).toEqual([path.join(workspaceRoot, "out.txt")]);
    expect(result.wrongTreeMatches).toEqual([]);
  });

  test("classifies same relpath under wrong-tree root as artifact-wrong-tree", async () => {
    await fs.writeFile(path.join(wrongRoot, "out.txt"), "done");
    const result = await verifyWorkflowArtifacts({
      requiredArtifacts: ["out.txt"],
      wrongTreeRoots: [wrongRoot],
      workspaceRoot,
    });
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.kind).toBe("artifact-wrong-tree");
    expect(result.wrongTreeMatches).toEqual([
      {
        expectedPath: path.join(workspaceRoot, "out.txt"),
        foundAt: path.join(wrongRoot, "out.txt"),
      },
    ]);
  });

  test("treats paths that escape workspaceRoot as missing rather than verified", async () => {
    const result = await verifyWorkflowArtifacts({
      requiredArtifacts: ["../escape.txt"],
      workspaceRoot,
    });
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.kind).toBe("artifact-missing");
  });
});

describe("runExecProcess with workflow artifact contract", () => {
  test("A: happy path — artifact produced → completed + artifact-verified", async () => {
    const artifactPath = path.join(workspaceRoot, "report.json").replace(/\\/g, "\\\\");
    const { outcome, finished } = await runWithContract({
      command: `node -e "require('fs').writeFileSync('${artifactPath}', '{}')"`,
      workflowArtifacts: {
        requiredArtifacts: ["report.json"],
        workspaceRoot,
      },
    });
    expect(outcome.status).toBe("completed");
    expect(finished?.status).toBe("completed");
    expect(finished?.closureKind).toBe("artifact-verified");
  });

  test("B: missing artifact — process exits 0 → failed + artifact-missing", async () => {
    const { outcome, finished } = await runWithContract({
      command: `node -e "console.log('did not write anything')"`,
      workflowArtifacts: {
        requiredArtifacts: ["report.json"],
        workspaceRoot,
      },
    });
    expect(outcome.status).toBe("failed");
    if (outcome.status !== "failed") {
      return;
    }
    expect(outcome.failureKind).toBe("artifact-missing");
    expect(outcome.reason).toContain("were not produced");
    expect(finished?.status).toBe("failed");
    expect(finished?.closureKind).toBe("artifact-missing");
  });

  test("C: wrong-tree materialization — artifact written under wrong root → artifact-wrong-tree", async () => {
    const artifactPath = path.join(wrongRoot, "report.json").replace(/\\/g, "\\\\");
    const { outcome, finished } = await runWithContract({
      command: `node -e "require('fs').writeFileSync('${artifactPath}', '{}')"`,
      workflowArtifacts: {
        requiredArtifacts: ["report.json"],
        wrongTreeRoots: [wrongRoot],
        workspaceRoot,
      },
    });
    expect(outcome.status).toBe("failed");
    if (outcome.status !== "failed") {
      return;
    }
    expect(outcome.failureKind).toBe("artifact-wrong-tree");
    expect(outcome.reason).toContain("wrong tree");
    expect(outcome.reason).toContain(path.join(wrongRoot, "report.json"));
    expect(finished?.status).toBe("failed");
    expect(finished?.closureKind).toBe("artifact-wrong-tree");
  });

  test("D: no contract — generic exec retains lifecycle-only behavior and no closureKind", async () => {
    const { outcome, finished } = await runWithContract({
      command: `node -e "console.log('hello')"`,
    });
    expect(outcome.status).toBe("completed");
    expect(finished?.status).toBe("completed");
    expect(finished?.closureKind).toBeUndefined();
  });

  test("lifecycle failure under contract is persisted as lifecycle-only, not artifact-verified", async () => {
    const { outcome, finished } = await runWithContract({
      // Shell exits 127 for unknown command → lifecycle-level failure, so
      // artifact verification never runs and closureKind must be
      // "lifecycle-only" rather than a misleading "artifact-verified".
      command: `this-command-does-not-exist-openclaw-workflow-test`,
      workflowArtifacts: {
        requiredArtifacts: ["report.json"],
        workspaceRoot,
      },
    });
    expect(outcome.status).toBe("failed");
    if (outcome.status !== "failed") {
      return;
    }
    expect(outcome.failureKind).toBe("shell-command-not-found");
    expect(finished?.status).toBe("failed");
    expect(finished?.closureKind).toBe("lifecycle-only");
  });
});

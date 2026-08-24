import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { exportReleaseEvidence, verifyReleaseEvidence } from "../scripts/export-release-evidence.mjs";
import { RELEASE_OPERATION_CONTRACT, RELEASE_OPERATION_FILES } from "../scripts/release-operations.mjs";

const EXPECTED_OPERATION_PATHS = [
  "operations/check-cutover-readiness.ps1",
  "operations/cutover-release.ps1",
  "operations/switch-release.ps1",
  "operations/inspect-install.ps1",
  "operations/protect-state.ps1",
  "operations/configure-clients.ps1",
  "operations/cutover-lock.psm1",
  "operations/cutover-quiescence.psm1",
];

test("release evidence exporter verifies identity and creates synchronized immutable sanitized artifacts", async () => {
  const fixture = await createFixture();
  try {
    const result = await exportReleaseEvidence({
      descriptorPath: fixture.descriptorPath,
      outputDir: fixture.outputDir,
    });
    assert.equal(result.status, "exported");
    assert.equal(result.disposition, "candidate-ready-promotion-blocked");
    const packetBytes = await readFile(result.reportPath);
    const packetText = packetBytes.toString("utf8");
    const packet = JSON.parse(packetText);
    const markdown = await readFile(result.markdownPath, "utf8");
    const manifest = JSON.parse(await readFile(result.manifestPath, "utf8"));
    assert.equal(packet.candidate.gitSha, fixture.gitSha);
    assert.equal(packet.candidate.runtimeSha256, fixture.runtimeSha256);
    assert.deepEqual(RELEASE_OPERATION_FILES.map(({ target }) => target), EXPECTED_OPERATION_PATHS);
    assert.equal(packet.candidate.operations.length, 8);
    assert.deepEqual(packet.candidate.operations, fixture.operations.map(({ relative, bytes }) => ({
      path: relative,
      bytes: bytes.byteLength,
      sha256: sha256(bytes),
    })));
    assert.equal(packet.checks.find((check) => check.id === "repository-verify").status, "pass");
    assert.equal(packet.checks.find((check) => check.id === "manus-live").status, "blocked");
    assert.equal(manifest.files["evidence-report.json"].sha256, sha256(packetBytes));
    assert.equal((await verifyReleaseEvidence({ packetDir: fixture.outputDir })).status, "verified");
    assert.match(markdown, new RegExp(sha256(packetBytes)));
    assert.doesNotMatch(packetText, /C:\\\\Users\\\\Test Creator/i);
  assert.doesNotMatch(packetText, /sk-test-fixture-EXPOSED_SECRET_VALUE/i);
    const exportedLog = await readFile(join(fixture.outputDir, "artifacts", "repository-verify--repository-verify-log.txt"), "utf8");
    assert.match(exportedLog, /<workspace>/);
    assert.match(exportedLog, /<redacted-secret>/);
    assert.doesNotMatch(exportedLog, /Test Creator|EXPOSED_SECRET_VALUE/);
    const exportedJson = await readFile(join(fixture.outputDir, "artifacts", "json-check--json-log.json"), "utf8");
    assert.match(exportedJson, /<workspace>/);
    assert.match(exportedJson, /<redacted-secret>/);
    assert.doesNotMatch(exportedJson, /Test Creator|EXPOSED_SECRET_VALUE/);
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: fixture.descriptorPath, outputDir: fixture.outputDir }),
      /refusing to overwrite/i,
    );
  } finally {
    await fixture.cleanup();
  }
});

test("release evidence verifier detects report, artifact, and inventory tampering", async () => {
  for (const target of ["report", "artifact", "inventory"]) {
    const fixture = await createFixture();
    try {
      await exportReleaseEvidence({ descriptorPath: fixture.descriptorPath, outputDir: fixture.outputDir });
      if (target === "report") await writeFile(join(fixture.outputDir, "evidence-report.json"), "{}\n");
      if (target === "artifact") await writeFile(join(fixture.outputDir, "artifacts", "repository-verify--repository-verify-log.txt"), "tampered\n");
      if (target === "inventory") await writeFile(join(fixture.outputDir, "unmanifested.txt"), "unexpected\n");
      await assert.rejects(
        verifyReleaseEvidence({ packetDir: fixture.outputDir }),
        /(?:hash differs|byte count differs|unmanifested entries)/i,
      );
    } finally {
      await fixture.cleanup();
    }
  }
});

test("a failed competing exporter cannot delete another exporter's lock", async () => {
  const fixture = await createFixture();
  const lockPath = `${fixture.outputDir}.lock`;
  const owner = `${JSON.stringify({ schemaVersion: 1, packetId: "owner", pid: 1, token: "owner-token" })}\n`;
  try {
    await writeFile(lockPath, owner, { flag: "wx" });
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: fixture.descriptorPath, outputDir: fixture.outputDir }),
      /EEXIST|file already exists/i,
    );
    assert.equal(await readFile(lockPath, "utf8"), owner);
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: fixture.descriptorPath, outputDir: fixture.outputDir }),
      /EEXIST|file already exists/i,
    );
    assert.equal(await readFile(lockPath, "utf8"), owner);
  } finally {
    await fixture.cleanup();
  }
});

test("release evidence exporter fails closed on installed identity drift and leaves no output", async () => {
  const fixture = await createFixture();
  try {
    const descriptor = JSON.parse(await readFile(fixture.descriptorPath, "utf8"));
    descriptor.candidate.runtimeSha256 = "f".repeat(64);
    await writeFile(fixture.descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`);
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: fixture.descriptorPath, outputDir: fixture.outputDir }),
      /release metadata runtime hash differs/i,
    );
    await assert.rejects(readdir(fixture.outputDir));
  } finally {
    await fixture.cleanup();
  }
});

test("require-accepted refuses incomplete required gates and accepts complete gate coverage", async () => {
  const blockedFixture = await createFixture();
  try {
    const descriptor = JSON.parse(await readFile(blockedFixture.descriptorPath, "utf8"));
    descriptor.disposition = "accepted";
    await writeFile(blockedFixture.descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`);
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: blockedFixture.descriptorPath, outputDir: blockedFixture.outputDir, requireAccepted: true }),
      /required checks are incomplete/i,
    );
  } finally {
    await blockedFixture.cleanup();
  }

  const acceptedFixture = await createFixture({ accepted: true });
  try {
    const result = await exportReleaseEvidence({
      descriptorPath: acceptedFixture.descriptorPath,
      outputDir: acceptedFixture.outputDir,
      requireAccepted: true,
    });
    assert.equal(result.status, "accepted");
    assert.equal(result.disposition, "accepted-with-residual-risks");
  } finally {
    await acceptedFixture.cleanup();
  }
});

test("release evidence exporter rejects unknown descriptor fields and output within install root", async () => {
  const fixture = await createFixture();
  try {
    const descriptor = JSON.parse(await readFile(fixture.descriptorPath, "utf8"));
    descriptor.surprise = true;
    await writeFile(fixture.descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`);
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: fixture.descriptorPath, outputDir: fixture.outputDir }),
      /missing or unknown fields/i,
    );
    delete descriptor.surprise;
    await writeFile(fixture.descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`);
    await assert.rejects(
      exportReleaseEvidence({
        descriptorPath: fixture.descriptorPath,
        outputDir: join(fixture.installRoot, descriptor.packetId),
      }),
      /outside the Agent Bridge install root/i,
    );
  } finally {
    await fixture.cleanup();
  }
});

test("release evidence exporter binds the bundle and shared config to the installed candidate", async () => {
  const bundleFixture = await createFixture();
  try {
    const descriptor = JSON.parse(await readFile(bundleFixture.descriptorPath, "utf8"));
    const metadata = await readFile(join(bundleFixture.releasePath, "release-metadata.json"));
    const manifest = await readFile(join(bundleFixture.releasePath, "manifest.json"));
    const unrelatedBundle = zipStore([
      { relative: "manifest.json", bytes: manifest },
      { relative: "release-metadata.json", bytes: metadata },
      { relative: "server/agent-bridge.mjs", bytes: Buffer.from("// unrelated runtime\n") },
      { relative: "server/agent-bridge.mjs.map", bytes: bundleFixture.sourceMap },
      ...bundleFixture.operations,
    ]);
    await writeFile(bundleFixture.bundlePath, unrelatedBundle);
    descriptor.candidate.bundleSha256 = sha256(unrelatedBundle);
    await writeFile(bundleFixture.descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`);
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: bundleFixture.descriptorPath, outputDir: bundleFixture.outputDir }),
      /candidate bundle payload differs.*server\/agent-bridge\.mjs/i,
    );
  } finally {
    await bundleFixture.cleanup();
  }

  const configFixture = await createFixture();
  try {
    const descriptor = JSON.parse(await readFile(configFixture.descriptorPath, "utf8"));
    const alternate = join(configFixture.root, "alternate-config.json");
    await writeFile(alternate, await readFile(descriptor.candidate.configPath));
    descriptor.candidate.configPath = alternate;
    await writeFile(configFixture.descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`);
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: configFixture.descriptorPath, outputDir: configFixture.outputDir }),
      /shared config directly under installRoot/i,
    );
  } finally {
    await configFixture.cleanup();
  }
});

test("release evidence exporter rejects immutable operation drift, omission, contract mismatch, and extras", async () => {
  for (const scenario of ["installed-tamper", "bundle-tamper", "missing-operation", "contract-mismatch", "unexpected-installed", "unexpected-bundle"]) {
    const fixture = await createFixture();
    try {
      const descriptor = JSON.parse(await readFile(fixture.descriptorPath, "utf8"));
      const operation = fixture.operations[0];
      if (scenario === "installed-tamper") {
        await writeFile(join(fixture.releasePath, ...operation.relative.split("/")), "# tampered installed operation\n");
      } else if (scenario === "bundle-tamper") {
        const entries = fixture.bundleEntries.map((entry) => entry.relative === operation.relative
          ? { ...entry, bytes: Buffer.from("# tampered bundle operation\n") }
          : entry);
        const bundle = zipStore(entries);
        await writeFile(fixture.bundlePath, bundle);
        descriptor.candidate.bundleSha256 = sha256(bundle);
      } else if (scenario === "missing-operation") {
        await rm(join(fixture.releasePath, ...operation.relative.split("/")));
      } else if (scenario === "contract-mismatch") {
        const metadataPath = join(fixture.releasePath, "release-metadata.json");
        const metadata = JSON.parse(await readFile(metadataPath, "utf8"));
        metadata.operations = { ...RELEASE_OPERATION_CONTRACT, platform: "unsupported" };
        const metadataBytes = Buffer.from(`${JSON.stringify(metadata, null, 2)}\n`);
        await writeFile(metadataPath, metadataBytes);
        const bundle = zipStore(fixture.bundleEntries.map((entry) => entry.relative === "release-metadata.json" ? { ...entry, bytes: metadataBytes } : entry));
        await writeFile(fixture.bundlePath, bundle);
        descriptor.candidate.bundleSha256 = sha256(bundle);
      } else if (scenario === "unexpected-installed") {
        const unexpected = join(fixture.releasePath, "operations", "unlisted.ps1");
        await writeFile(unexpected, "throw 'unlisted'\n");
      } else {
        const bundle = zipStore([...fixture.bundleEntries, { relative: "operations/unlisted.ps1", bytes: Buffer.from("throw 'unlisted'\n") }]);
        await writeFile(fixture.bundlePath, bundle);
        descriptor.candidate.bundleSha256 = sha256(bundle);
      }
      await writeFile(fixture.descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`);
      const expected = {
        "installed-tamper": /installed payload (?:byte count|hash) differs.*operations\/check-cutover-readiness\.ps1/i,
        "bundle-tamper": /candidate bundle payload differs.*operations\/check-cutover-readiness\.ps1/i,
        "missing-operation": /installed release inventory is incomplete/i,
        "contract-mismatch": /immutable-operation contract is missing or unsupported/i,
        "unexpected-installed": /installed release inventory is incomplete or contains unexpected files/i,
        "unexpected-bundle": /candidate bundle inventory is incomplete or contains unexpected files/i,
      }[scenario];
      await assert.rejects(
        exportReleaseEvidence({ descriptorPath: fixture.descriptorPath, outputDir: fixture.outputDir }),
        expected,
        scenario,
      );
      await assert.rejects(readdir(fixture.outputDir));
    } finally {
      await fixture.cleanup();
    }
  }
});

test("accepted export requires the promoted marker and every named client gate", async () => {
  const markerFixture = await createFixture({ accepted: true });
  try {
    const markerPath = join(markerFixture.installRoot, "current-release.json");
    const marker = JSON.parse(await readFile(markerPath, "utf8"));
    marker.releaseId = "0.2.1+4785d63";
    await writeFile(markerPath, `${JSON.stringify(marker, null, 2)}\n`);
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: markerFixture.descriptorPath, outputDir: markerFixture.outputDir, requireAccepted: true }),
      /promotion marker does not name the candidate/i,
    );
  } finally {
    await markerFixture.cleanup();
  }

  const clientFixture = await createFixture({ accepted: true });
  try {
    const descriptor = JSON.parse(await readFile(clientFixture.descriptorPath, "utf8"));
    descriptor.checks = descriptor.checks.filter((check) => check.id !== "claude-desktop-restarted-client");
    await writeFile(clientFixture.descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`);
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: clientFixture.descriptorPath, outputDir: clientFixture.outputDir, requireAccepted: true }),
      /claude-desktop-restarted-client/i,
    );
  } finally {
    await clientFixture.cleanup();
  }

  const windowsFixture = await createFixture({ accepted: true });
  try {
    const descriptor = JSON.parse(await readFile(windowsFixture.descriptorPath, "utf8"));
    descriptor.checks = descriptor.checks.filter((check) => check.id !== "windows-npm-shim-installed-runtime");
    await writeFile(windowsFixture.descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`);
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: windowsFixture.descriptorPath, outputDir: windowsFixture.outputDir, requireAccepted: true }),
      /windows-npm-shim-installed-runtime/i,
    );
  } finally {
    await windowsFixture.cleanup();
  }

  const gateFixture = await createFixture({ accepted: true });
  try {
    const descriptor = JSON.parse(await readFile(gateFixture.descriptorPath, "utf8"));
    descriptor.checks.find((check) => check.id === "manus-remote-canary").gate = "automated";
    await writeFile(gateFixture.descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`);
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: gateFixture.descriptorPath, outputDir: gateFixture.outputDir, requireAccepted: true }),
      /manus-remote-canary to use the remote-service gate/i,
    );
  } finally {
    await gateFixture.cleanup();
  }

  const shimFixture = await createFixture({ accepted: true });
  try {
    const wrongRelease = "0.3.0-rc.1+abcdef0";
    await writeFile(join(shimFixture.installRoot, "agent-bridge.mjs"), `// ./releases/${shimFixture.releaseId}/server/agent-bridge.mjs\nawait import(new URL("./releases/${wrongRelease}/server/agent-bridge.mjs", import.meta.url).href);\n`);
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: shimFixture.descriptorPath, outputDir: shimFixture.outputDir, requireAccepted: true }),
      /stable shim runtime does not exist/i,
    );
  } finally {
    await shimFixture.cleanup();
  }
});

test("evidence inputs are contained by the declared root and restricted data is rejected", async () => {
  const escapeFixture = await createFixture();
  try {
    const descriptor = JSON.parse(await readFile(escapeFixture.descriptorPath, "utf8"));
    const check = descriptor.checks.find((item) => item.id === "repository-verify");
    check.evidence[0].path = descriptor.candidate.configPath;
    check.evidence[0].expectedSha256 = descriptor.candidate.configSha256;
    await writeFile(escapeFixture.descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`);
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: escapeFixture.descriptorPath, outputDir: escapeFixture.outputDir }),
      /escapes descriptor.evidenceRoot/i,
    );
  } finally {
    await escapeFixture.cleanup();
  }

  const restrictedFixture = await createFixture();
  try {
    const descriptor = JSON.parse(await readFile(restrictedFixture.descriptorPath, "utf8"));
    descriptor.checks[0].evidence[0].dataClass = "restricted";
    await writeFile(restrictedFixture.descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`);
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: restrictedFixture.descriptorPath, outputDir: restrictedFixture.outputDir }),
      /cannot be copied to a shareable packet/i,
    );
  } finally {
    await restrictedFixture.cleanup();
  }
});

test("release evidence exporter excludes private state/session inputs and fails closed on Manus task IDs", async () => {
  const stateFixture = await createFixture();
  try {
    const descriptor = JSON.parse(await readFile(stateFixture.descriptorPath, "utf8"));
    const stateDir = join(dirname(stateFixture.descriptorPath), "state");
    const privateState = join(stateDir, "sessions.json");
    await mkdir(stateDir);
    await writeFile(privateState, JSON.stringify({ nativeTaskId: "A".repeat(22) }));
    const check = descriptor.checks.find((item) => item.id === "repository-verify");
    check.evidence[0].path = privateState;
    check.evidence[0].expectedSha256 = sha256(await readFile(privateState));
    await writeFile(stateFixture.descriptorPath, JSON.stringify(descriptor, null, 2) + "\n");
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: stateFixture.descriptorPath, outputDir: stateFixture.outputDir }),
      /private state\/session evidence/i,
    );
    await assert.rejects(readdir(stateFixture.outputDir));
  } finally {
    await stateFixture.cleanup();
  }

  const taskIdFixture = await createFixture();
  try {
    const descriptor = JSON.parse(await readFile(taskIdFixture.descriptorPath, "utf8"));
    const check = descriptor.checks.find((item) => item.id === "repository-verify");
    const publicLog = check.evidence[0].path;
    await writeFile(publicLog, "public log with native id " + "B".repeat(22) + "\n");
    check.evidence[0].expectedSha256 = sha256(await readFile(publicLog));
    await writeFile(taskIdFixture.descriptorPath, JSON.stringify(descriptor, null, 2) + "\n");
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: taskIdFixture.descriptorPath, outputDir: taskIdFixture.outputDir }),
      /provider-native Manus task ID/i,
    );
    await assert.rejects(readdir(taskIdFixture.outputDir));
  } finally {
    await taskIdFixture.cleanup();
  }

  const safeJsonFixture = await createFixture();
  try {
    const descriptor = JSON.parse(await readFile(safeJsonFixture.descriptorPath, "utf8"));
    const check = descriptor.checks.find((item) => item.id === "repository-verify");
    const evidence = check.evidence[0];
    await writeFile(evidence.path, JSON.stringify({ implementationPriority: "P1", nested: { status: "safe" } }));
    evidence.mediaType = "application/json";
    evidence.expectedSha256 = sha256(await readFile(evidence.path));
    await writeFile(safeJsonFixture.descriptorPath, JSON.stringify(descriptor, null, 2) + "\n");
    await exportReleaseEvidence({ descriptorPath: safeJsonFixture.descriptorPath, outputDir: safeJsonFixture.outputDir });
    const exported = JSON.parse(await readFile(join(safeJsonFixture.outputDir, "artifacts", check.id + "--" + evidence.id + ".json"), "utf8"));
    assert.deepEqual(exported, { implementationPriority: "P1", nested: { status: "safe" } });
  } finally {
    await safeJsonFixture.cleanup();
  }

  for (const candidate of [
    { mediaType: "text/plain", content: "implementationPriority is a documented field\n", extension: ".txt" },
    { mediaType: "text/markdown", content: "## implementationPriority\n\nDocumented release field.\n", extension: ".md" },
  ]) {
    const safeTextFixture = await createFixture();
    try {
      const descriptor = JSON.parse(await readFile(safeTextFixture.descriptorPath, "utf8"));
      const check = descriptor.checks.find((item) => item.id === "repository-verify");
      const evidence = check.evidence[0];
      await writeFile(evidence.path, candidate.content);
      evidence.mediaType = candidate.mediaType;
      evidence.expectedSha256 = sha256(await readFile(evidence.path));
      await writeFile(safeTextFixture.descriptorPath, JSON.stringify(descriptor, null, 2) + "\n");
      await exportReleaseEvidence({ descriptorPath: safeTextFixture.descriptorPath, outputDir: safeTextFixture.outputDir });
      const exported = await readFile(join(safeTextFixture.outputDir, "artifacts", check.id + "--" + evidence.id + candidate.extension), "utf8");
      assert.match(exported, /implementationPriority/);
    } finally {
      await safeTextFixture.cleanup();
    }
  }
});

test("release evidence exporter rejects Manus task IDs in JSON keys", async () => {
  const fixture = await createFixture();
  try {
    const descriptor = JSON.parse(await readFile(fixture.descriptorPath, "utf8"));
    const check = descriptor.checks.find((item) => item.id === "repository-verify");
    const evidence = check.evidence[0];
    await writeFile(evidence.path, JSON.stringify({ ["C".repeat(22)]: "provider-native key" }));
    evidence.mediaType = "application/json";
    evidence.expectedSha256 = sha256(await readFile(evidence.path));
    await writeFile(fixture.descriptorPath, JSON.stringify(descriptor, null, 2) + "\n");
    await assert.rejects(
      exportReleaseEvidence({ descriptorPath: fixture.descriptorPath, outputDir: fixture.outputDir }),
      /provider-native Manus task ID/i,
    );
    await assert.rejects(readdir(fixture.outputDir));
  } finally {
    await fixture.cleanup();
  }
});

test("release evidence exporter redacts renamed private JSON narratives and native identifiers", async () => {
  const fixture = await createFixture();
  try {
    const descriptor = JSON.parse(await readFile(fixture.descriptorPath, "utf8"));
    const check = descriptor.checks.find((item) => item.id === "repository-verify");
    const evidence = check.evidence[0];
    const renamedState = join(dirname(fixture.descriptorPath), "review.json");
    const nativeTaskId = "D".repeat(22);
    await writeFile(renamedState, JSON.stringify({
      prompt: "private customer prompt",
      transcripts: ["private transcript"],
      assistantResponse: "private response",
      promptText: "private prompt text",
      messages: [{ content: "private message" }],
      turns: [{ prompt: "private turn prompt", response: "private turn response" }],
      nativeTaskId,
      nativeSessions: { manus: nativeTaskId, claude: "private-native-session" },
      claudeRaw: { session_id: "claude-native-smoke", result: "private Claude transcript" },
      codexRaw: { thread_id: "codex-native-smoke", item: { text: "private Codex transcript" } },
      geminiRaw: { response: "private Gemini transcript", result: "private Gemini fallback" },
      nested: { status: "safe" },
    }));
    evidence.path = renamedState;
    evidence.mediaType = "application/json";
    evidence.expectedSha256 = sha256(await readFile(renamedState));
    await writeFile(fixture.descriptorPath, JSON.stringify(descriptor, null, 2) + "\n");
    await exportReleaseEvidence({ descriptorPath: fixture.descriptorPath, outputDir: fixture.outputDir });
    const exportedPath = join(fixture.outputDir, "artifacts", check.id + "--" + evidence.id + ".json");
    const exportedText = await readFile(exportedPath, "utf8");
    const exported = JSON.parse(exportedText);
    assert.equal(exported.prompt, "<redacted-narrative>");
    assert.equal(exported.transcripts, "<redacted-narrative>");
    assert.equal(exported.assistantResponse, "<redacted-narrative>");
    assert.equal(exported.promptText, "<redacted-narrative>");
    assert.equal(exported.messages, "<redacted-narrative>");
    assert.equal(exported.turns, "<redacted-narrative>");
    assert.equal(exported.nativeTaskId, "<redacted-provider-identifier>");
    assert.equal(exported.nativeSessions, "<redacted-provider-identifier>");
    assert.equal(exported.claudeRaw.session_id, "<redacted-provider-identifier>");
    assert.equal(exported.claudeRaw.result, "<redacted-narrative>");
    assert.equal(exported.codexRaw.thread_id, "<redacted-provider-identifier>");
    assert.equal(exported.codexRaw.item.text, "<redacted-narrative>");
    assert.equal(exported.geminiRaw.response, "<redacted-narrative>");
    assert.equal(exported.geminiRaw.result, "<redacted-narrative>");
    assert.deepEqual(exported.nested, { status: "safe" });
    assert.doesNotMatch(exportedText, /private customer|private transcript|private response|private message|private turn|private-native-session|private Claude|private Codex|private Gemini|claude-native-smoke|codex-native-smoke/);
    assert.doesNotMatch(exportedText, new RegExp(nativeTaskId));
  } finally {
    await fixture.cleanup();
  }
});

test("descriptor narratives are sanitized and escaped before JSON and Markdown export", async () => {
  const fixture = await createFixture();
  try {
    const descriptor = JSON.parse(await readFile(fixture.descriptorPath, "utf8"));
  const hostile = "prompt: private transcript sk-test-fixture-EXPOSED_SECRET_VALUE_1234567890 at C:\\Unlisted\\private\\record.txt ![x](https://tracker.invalid/pixel)";
    descriptor.checks.find((check) => check.status === "blocked").reason = hostile;
    descriptor.agentRuns[0].reason = hostile;
    descriptor.recommendations.push({
      id: "hostile-recommendation",
      title: hostile,
      priority: "P2",
      sources: ["reviewer"],
      decision: "deferred",
      reason: hostile,
      workItemKey: null,
    });
    descriptor.residualRisks.push({
      id: "RR-hostile",
      risk: hostile,
      owner: hostile,
      disposition: "deferred",
      reviewAfter: "2026-09-13T00:00:00.000Z",
    });
    await writeFile(fixture.descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`);
    const result = await exportReleaseEvidence({ descriptorPath: fixture.descriptorPath, outputDir: fixture.outputDir });
    const output = `${await readFile(result.reportPath, "utf8")}\n${await readFile(result.markdownPath, "utf8")}`;
    assert.doesNotMatch(output, /EXPOSED_SECRET_VALUE|Unlisted|tracker\.invalid|private transcript/i);
    assert.doesNotMatch(await readFile(result.markdownPath, "utf8"), /!\[x\]\(/);
    assert.match(output, /redacted-(?:secret|narrative|url)/i);
  } finally {
    await fixture.cleanup();
  }
});

async function createFixture({ accepted = false } = {}) {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-evidence-export-test-"));
  const installRoot = join(root, "install");
  const version = "0.3.0-rc.2";
  const gitSha = "1234567890abcdef1234567890abcdef12345678";
  const releaseId = `${version}+${gitSha.slice(0, 7)}`;
  const releasePath = join(installRoot, "releases", releaseId);
  const runtimePath = join(releasePath, "server", "agent-bridge.mjs");
  const bundlePath = join(root, "agent-bridge.mcpb");
  const configPath = join(installRoot, "config.json");
  const evidenceRoot = join(root, "evidence");
  const evidenceSource = join(evidenceRoot, "verify.txt");
  const descriptorPath = join(evidenceRoot, "descriptor.json");
  const packetId = `agent-bridge-${releaseId}`;
  const outputDir = join(evidenceRoot, packetId);
  await mkdir(join(releasePath, "server"), { recursive: true });
  await mkdir(evidenceRoot, { recursive: true });
  const runtime = Buffer.from("// candidate runtime\n");
  const sourceMap = Buffer.from("{}\n");
  const operations = RELEASE_OPERATION_FILES.map(({ target }, index) => ({
    relative: target,
    bytes: Buffer.from(`# immutable operation ${index + 1}: ${target}\n`),
  }));
  const config = Buffer.from("{\"agents\":{}}\n");
  const runtimeSha256 = sha256(runtime);
  const payloads = [
    { relative: "server/agent-bridge.mjs", bytes: runtime },
    { relative: "server/agent-bridge.mjs.map", bytes: sourceMap },
    ...operations,
  ];
  const metadataBytes = Buffer.from(`${JSON.stringify({
    package: "agent-bridge-mcp",
    version,
    builtAt: "2026-08-13T00:00:00.000Z",
    gitSha,
    operations: RELEASE_OPERATION_CONTRACT,
    files: Object.fromEntries(payloads.map(({ relative, bytes }) => [relative, { sha256: sha256(bytes), bytes: bytes.byteLength }])),
  }, null, 2)}\n`);
  const manifestBytes = Buffer.from(`${JSON.stringify({
    manifest_version: "0.3",
    version,
    _meta: { "com.agentbridge.release": { source_git_sha: gitSha, runtime_sha256: runtimeSha256 } },
  }, null, 2)}\n`);
  const bundleEntries = [
    { relative: "manifest.json", bytes: manifestBytes },
    { relative: "release-metadata.json", bytes: metadataBytes },
    ...payloads,
  ];
  const bundle = zipStore(bundleEntries);
  for (const { relative, bytes } of payloads) {
    const path = join(releasePath, ...relative.split("/"));
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, bytes);
  }
  await writeFile(bundlePath, bundle);
  await writeFile(configPath, config);
  await writeFile(join(releasePath, "release-metadata.json"), metadataBytes);
  await writeFile(join(releasePath, "manifest.json"), manifestBytes);
  await writeFile(evidenceSource, "C:\\Users\\Test Creator\\project passed with sk-test-fixture-EXPOSED_SECRET_VALUE_1234567890\n");
  const jsonEvidenceSource = join(evidenceRoot, "structured.json");
  await writeFile(jsonEvidenceSource, `${JSON.stringify({
    path: "C:\\Users\\Test Creator\\project\\artifact.txt",
      apiKey: "sk-test-fixture-EXPOSED_SECRET_VALUE_1234567890",
  })}\n`);
  const sourceEvidenceSha256 = sha256(await readFile(evidenceSource));
  const jsonEvidenceSha256 = sha256(await readFile(jsonEvidenceSource));
  const passCheck = (id, gate) => ({
    id,
    gate,
    status: "pass",
    source: "operator-attested",
    required: true,
    performedAt: "2026-08-13T00:00:00.000Z",
    reason: null,
    command: `run ${id}`,
    exitCode: 0,
    evidence: [{ id: `${id}-log`, path: evidenceSource, mediaType: "text/plain", dataClass: "internal", expectedSha256: sourceEvidenceSha256 }],
  });
  const jsonCheck = {
    id: "json-check",
    gate: "automated",
    status: "pass",
    source: "operator-attested",
    required: false,
    performedAt: "2026-08-13T00:00:00.000Z",
    reason: null,
    command: "inspect structured evidence",
    exitCode: 0,
    evidence: [{ id: "json-log", path: jsonEvidenceSource, mediaType: "application/json", dataClass: "internal", expectedSha256: jsonEvidenceSha256 }],
  };
  const checks = accepted
    ? [
        passCheck("repository-verify", "automated"),
        passCheck("production-dependency-audit", "automated"),
        passCheck("mcpb-manifest-validation", "automated"),
        passCheck("immutable-operations-integrity", "automated"),
        passCheck("installed-provider-disabled-canary", "automated"),
        passCheck("windows-npm-shim-installed-runtime", "automated"),
        passCheck("codex-installed-runtime", "local-cli"),
        passCheck("claude-installed-runtime", "local-cli"),
        passCheck("registration-normalization", "client-restart"),
        passCheck("release-promotion", "client-restart"),
        passCheck("manus-remote-canary", "remote-service"),
        passCheck("manus-waiting-action-canary", "remote-service"),
        passCheck("codex-restarted-client", "client-restart"),
        passCheck("claude-code-restarted-client", "client-restart"),
        passCheck("claude-desktop-restarted-client", "client-restart"),
        passCheck("creator-visible-acceptance", "human-visible"),
        passCheck("rollback-canary", "automated"),
        jsonCheck,
      ]
    : [
        passCheck("repository-verify", "automated"),
        jsonCheck,
        {
          id: "manus-live",
          gate: "remote-service",
          status: "blocked",
          source: "operator-attested",
          required: true,
          performedAt: null,
          reason: "Replacement credential requires user confirmation.",
          command: null,
          exitCode: null,
          evidence: [],
        },
      ];
  const descriptor = {
    schemaVersion: 1,
    packetId,
    evidenceRoot,
    sanitization: {
      method: "Replaced private path prefixes and secret-shaped values; omitted prompts and transcripts.",
      redactions: [{ path: "C:\\Users\\Test Creator\\project", replacement: "<workspace>" }],
    },
    candidate: {
      version,
      gitSha,
      releaseId,
      installRoot,
      releasePath,
      bundlePath,
      bundleSha256: sha256(bundle),
      runtimeSha256,
      configPath,
      configSha256: sha256(config),
      liveAtStart: "0.2.1+4785d63",
      liveAtEnd: accepted ? releaseId : "0.2.1+4785d63",
    },
    checks,
    approvals: [],
    agentRuns: accepted
      ? [{ id: "run-codex", agent: "codex", boundary: "local-cli", status: "pass", reason: null, sessionRef: "session-1", outputCheckId: "codex-installed-runtime" }]
      : [{ id: "run-manus", agent: "manus", boundary: "remote-service", status: "blocked", reason: "Credential unavailable.", sessionRef: null, outputCheckId: "manus-live" }],
    recommendations: [],
    workboard: null,
    budget: { enabled: false, currency: null, maxReservedCents: null, reservedCents: null },
    residualRisks: accepted
      ? [{ id: "RR-001", risk: "Human-visible behavior remains subjective.", owner: "maintainer", disposition: "accepted", reviewAfter: "2026-09-13T00:00:00.000Z" }]
      : [],
    rollback: {
      priorReleaseId: "0.2.1+4785d63",
      priorRuntimeSha256: "e".repeat(64),
      backupRef: "artifact://backups/prior",
      canaryStatus: accepted ? "pass" : "not-run",
    },
    disposition: accepted ? "accepted-with-residual-risks" : "candidate-ready-promotion-blocked",
  };
  if (accepted) {
    const priorReleaseId = descriptor.rollback.priorReleaseId;
    const priorRuntimePath = join(installRoot, "releases", priorReleaseId, "server", "agent-bridge.mjs");
    await mkdir(join(installRoot, "releases", priorReleaseId, "server"), { recursive: true });
    await writeFile(priorRuntimePath, Buffer.from("prior runtime\n"));
    descriptor.rollback.priorRuntimeSha256 = sha256(await readFile(priorRuntimePath));
    const backupPath = join(installRoot, "backups", "prior");
    await mkdir(backupPath, { recursive: true });
    await writeFile(join(installRoot, "current-release.json"), `${JSON.stringify({
      schemaVersion: 1,
      releaseId,
      releasePath,
      runtimeSha256,
      promotedAt: "2026-08-13T00:00:00.000Z",
      backupPath,
    }, null, 2)}\n`);
    await writeFile(join(installRoot, "agent-bridge.mjs"), `await import(new URL("./releases/${releaseId}/server/agent-bridge.mjs", import.meta.url).href);\n`);
  }
  await writeFile(descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`);
  return {
    root, installRoot, releasePath, bundlePath, descriptorPath, outputDir, gitSha, runtimeSha256,
    sourceMap, operations, bundleEntries, releaseId,
    cleanup: () => rm(root, { recursive: true, force: true }),
  };
}

function sha256(value) { return createHash("sha256").update(value).digest("hex"); }

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function u16(value) { const buffer = Buffer.alloc(2); buffer.writeUInt16LE(value); return buffer; }
function u32(value) { const buffer = Buffer.alloc(4); buffer.writeUInt32LE(value >>> 0); return buffer; }
function zipStore(entries) {
  const local = [];
  const central = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.relative);
    const crc = crc32(entry.bytes);
    const header = Buffer.concat([u32(0x04034b50), u16(20), u16(0), u16(0), u16(0), u16(0), u32(crc), u32(entry.bytes.length), u32(entry.bytes.length), u16(name.length), u16(0), name, entry.bytes]);
    local.push(header);
    central.push(Buffer.concat([u32(0x02014b50), u16(20), u16(20), u16(0), u16(0), u16(0), u16(0), u32(crc), u32(entry.bytes.length), u32(entry.bytes.length), u16(name.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(offset), name]));
    offset += header.length;
  }
  const localBytes = Buffer.concat(local);
  const centralBytes = Buffer.concat(central);
  return Buffer.concat([localBytes, centralBytes, u32(0x06054b50), u16(0), u16(0), u16(entries.length), u16(entries.length), u32(centralBytes.length), u32(localBytes.length), u16(0)]);
}

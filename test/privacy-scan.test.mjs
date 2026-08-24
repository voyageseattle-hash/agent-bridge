import assert from "node:assert/strict";
import test from "node:test";
import { scanPath, scanText } from "../scripts/scan-public.mjs";

test("public scanner accepts examples and never stores matched values", () => {
  const text = [
    "contact: maintainer@example.invalid",
    "root: C:\\\\Users\\\\alice\\\\project",
    "api_key: \"replace-me-with-your-key\"",
  ].join("\n");
  assert.deepEqual(scanText(text, "example.txt"), []);
  assert.deepEqual(scanText("legacy fixture sk-abcdefghijklmnopqrstuvwxyz123456", "test/fixture.mjs"), []);
});

test("public scanner blocks credentials with redacted findings", () => {
  const value = ["sk", "live", "DoNotPrintThisCredentialValue123456"].join("-");
  const findings = scanText(`api_key: "${value}"`, "unsafe.json");
  assert.equal(findings.length, 2);
  assert.deepEqual(new Set(findings.map((item) => item.category)), new Set(["openai-api-key", "credential-assignment"]));
  assert.equal(JSON.stringify(findings).includes(value), false);
});

test("public scanner blocks personal metadata and sensitive paths", () => {
  const privatePath = ["C:", "Users", "operator", "private"].join("\\");
  const personalEmail = ["owner", "personal.test"].join("@");
  assert.equal(scanText(privatePath, "doc.md")[0]?.category, "private-user-path");
  assert.equal(scanText(personalEmail, "doc.md")[0]?.category, "personal-email");
  assert.equal(scanPath("state/session.json")[0]?.category, "private-directory");
  assert.equal(scanPath("config.json")[0]?.category, "sensitive-file");
});

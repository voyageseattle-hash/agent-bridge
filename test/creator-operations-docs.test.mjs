import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("creator approval examples bind preview-returned full envelope hashes", async () => {
  for (const name of ["approval-request.example.json", "paid-approval-request.example.json"]) {
    const example = JSON.parse(await readFile("examples/" + name, "utf8"));
    assert.equal("payload" in example, false, name + " must not authorize prompt text as the payload");
    assert.equal(example.payload_sha256, "<preview_turn_approval.payload_sha256 for the exact full approval envelope>");
  }
});

test("creator operations documents actual preview cost and session semantics", async () => {
  const guide = await readFile("docs/CREATOR_OPERATIONS.md", "utf8");
  assert.match(guide, /It does not accept cost fields\./);
  assert.match(guide, /A new-session preview returns `session_revision: null`/);
  assert.match(guide, /without `session_id` and without `expected_session_revision`/);
  assert.match(guide, /exact preview-returned integer `expected_session_revision`/);
  assert.doesNotMatch(guide, /preview_turn_approval.*positive bounded cost estimate/);
});

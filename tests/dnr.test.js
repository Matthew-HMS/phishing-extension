import { test } from "node:test";
import assert from "node:assert/strict";
import { toUrlFilter, buildBlockRules, BYPASS_ID_BASE } from "../extension/lib/dnr.js";

test("toUrlFilter anchors host and host/path correctly", () => {
  assert.equal(toUrlFilter("evil.com"), "||evil.com^");
  assert.equal(toUrlFilter("evil.com/login"), "||evil.com/login");
});

test("toUrlFilter rejects unsupported keys", () => {
  assert.equal(toUrlFilter("ünicode.com"), null); // non-ASCII
  assert.equal(toUrlFilter("a.com/b*c"), null); // DNR meta-char
  assert.equal(toUrlFilter(""), null);
});

test("buildBlockRules produces valid redirect rules with unique ids", () => {
  const index = [
    ["evil.com/login", "phishing"],
    ["malware.test", "malware"],
    ["ünicode.com", "phishing"], // skipped (unsupported)
  ];
  const rules = buildBlockRules(index, (key, cat) => `warn?url=${key}&cat=${cat}`);
  assert.equal(rules.length, 2); // unicode entry dropped

  const ids = rules.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length); // unique
  assert.ok(ids.every((id) => id < BYPASS_ID_BASE)); // block-rule range

  const [first] = rules;
  assert.equal(first.action.type, "redirect");
  assert.equal(first.condition.urlFilter, "||evil.com/login");
  assert.deepEqual(first.condition.resourceTypes, ["main_frame"]);
  assert.match(first.action.redirect.url, /url=evil\.com\/login&cat=phishing/);
});

test("buildBlockRules honours the max cap", () => {
  const index = Array.from({ length: 50 }, (_, i) => [`x${i}.com`, "phishing"]);
  const rules = buildBlockRules(index, () => "warn", { max: 10 });
  assert.equal(rules.length, 10);
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { runHeuristics, levenshtein, entropy } from "../extension/lib/heuristics.js";

const score = (url) => runHeuristics(url).score;
const reasons = (url) => runHeuristics(url).reasons.join(" | ");

test("levenshtein + entropy primitives", () => {
  assert.equal(levenshtein("paypal", "paypa1"), 1);
  assert.equal(levenshtein("abc", "abc"), 0);
  assert.ok(entropy("aaaaaa") < entropy("a8x!q2"));
});

test("legitimate sites score clean", () => {
  assert.equal(score("https://www.google.com/search?q=x"), 0);
  assert.equal(score("https://www.esunbank.com.tw/personal"), 0);
  assert.equal(score("https://user.github.io/page"), 0);
});

test("typosquatting is detected, including on multi-part TLDs", () => {
  assert.match(reasons("https://paypa1.com/login"), /typosquatting/);
  // The PSL fix: this was previously missed because eTLD+1 was read as "com.tw".
  assert.match(reasons("https://paypa1.com.tw/login"), /typosquatting/);
});

test("brand mentioned outside the registrable domain is flagged", () => {
  assert.match(reasons("https://paypal.login.secure.evil.tw/"), /not the real paypal/);
  // ...but a brand embedded in a public suffix (github.io) is NOT a false positive.
  assert.doesNotMatch(reasons("https://user.github.io/page"), /github/);
});

test("structural red flags raise the score", () => {
  assert.ok(score("http://192.168.0.1/admin") >= 30); // raw IP
  assert.ok(score("https://xn--pple-43d.com/") >= 35); // punycode homograph
  assert.ok(score("https://login.secure.account.paypa1.xyz/signin") >= 70); // stacked
});

test("malformed URL is handled gracefully", () => {
  const r = runHeuristics("not a url");
  assert.equal(r.score, 0);
  assert.equal(r.hostname, null);
});

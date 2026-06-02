import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeKey, parseFeed } from "../extension/lib/blocklist.js";

test("normalizeKey drops scheme/query/fragment and trailing slash", () => {
  assert.equal(normalizeKey("https://evil.com/login?x=1#f"), "evil.com/login");
  assert.equal(normalizeKey("http://evil.com/login/"), "evil.com/login");
  assert.equal(normalizeKey("EVIL.com"), "evil.com");
});

test("a victim arriving with extra query still matches the feed entry", () => {
  const feedEntry = normalizeKey("https://phish.example/login");
  const navigation = normalizeKey("https://phish.example/login?session=abc");
  assert.equal(feedEntry, navigation);
});

test("scheme-less host/path entries are tolerated", () => {
  assert.equal(normalizeKey("bad-domain.tld/steal"), "bad-domain.tld/steal");
});

test("non-http(s) and junk are rejected", () => {
  assert.equal(normalizeKey("ftp://x.com/y"), null);
  assert.equal(normalizeKey("not a url"), null);
  assert.equal(normalizeKey(""), null);
});

test("parseFeed skips comments/blanks and tags categories", () => {
  const text = `# comment\nhttps://a.example/x\n\nhttps://b.example/y/`;
  const pairs = parseFeed(text, "phishing");
  assert.deepEqual(pairs, [
    ["a.example/x", "phishing"],
    ["b.example/y", "phishing"],
  ]);
});

test("parseFeed respects the cap", () => {
  const text = Array.from({ length: 100 }, (_, i) => `https://x${i}.com`).join("\n");
  assert.equal(parseFeed(text, "malware", 10).length, 10);
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { getPublicSuffix, getRegistrableDomain } from "../extension/lib/psl.js";

test("registrable domain for simple TLDs", () => {
  assert.equal(getRegistrableDomain("www.google.com"), "google.com");
  assert.equal(getRegistrableDomain("google.com"), "google.com");
  assert.equal(getRegistrableDomain("a.b.c.example.org"), "example.org");
});

test("multi-part suffixes (.tw / .co.uk) — the bug PSL fixes", () => {
  assert.equal(getPublicSuffix("www.esunbank.com.tw"), "com.tw");
  assert.equal(getRegistrableDomain("www.esunbank.com.tw"), "esunbank.com.tw");
  assert.equal(getRegistrableDomain("paypa1.com.tw"), "paypa1.com.tw");
  assert.equal(getRegistrableDomain("a.b.co.uk"), "b.co.uk");
  assert.equal(getPublicSuffix("bank.gov.tw"), "gov.tw");
});

test("private suffixes treat each subdomain as its own site", () => {
  assert.equal(getPublicSuffix("user.github.io"), "github.io");
  assert.equal(getRegistrableDomain("user.github.io"), "user.github.io");
  assert.equal(getRegistrableDomain("pages.github.io"), "pages.github.io");
});

test("wildcard and exception rules", () => {
  // *.ck makes any label under ck a suffix; !www.ck is the exception.
  assert.equal(getPublicSuffix("foo.bar.ck"), "bar.ck");
  assert.equal(getPublicSuffix("www.ck"), "ck");
  assert.equal(getRegistrableDomain("www.ck"), "www.ck");
});

test("no registrable part returns null", () => {
  assert.equal(getRegistrableDomain("com.tw"), null); // is itself a suffix
  assert.equal(getRegistrableDomain("1.2.3.4"), null); // IP
  assert.equal(getRegistrableDomain(""), null);
});

test("unknown TLD falls back to the default rule", () => {
  assert.equal(getPublicSuffix("example.somenewtld"), "somenewtld");
  assert.equal(getRegistrableDomain("example.somenewtld"), "example.somenewtld");
});

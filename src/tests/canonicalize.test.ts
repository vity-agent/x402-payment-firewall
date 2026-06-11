import assert from "node:assert/strict";
import test from "node:test";

import { canonicalizeUrl, domainMatches } from "../canonicalize.js";

test("canonicalizes host, default port, query order, and fragments", () => {
  assert.equal(
    canonicalizeUrl("https://API.Example.com:443/weather?z=2&a=1#ignored"),
    "https://api.example.com/weather?a=1&z=2",
  );
});

test("domain matching does not accept suffix confusion", () => {
  assert.equal(domainMatches("api.example.com", "example.com"), true);
  assert.equal(domainMatches("example.com.evil.test", "example.com"), false);
});

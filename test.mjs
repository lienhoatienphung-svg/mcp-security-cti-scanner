import assert from "node:assert";
import { scanTargetSecurity } from "./index.mjs";

const res = await scanTargetSecurity("github.com");
assert.strictEqual(res.target, "github.com");
assert.ok(res.httpStatus >= 200 && res.httpStatus < 400);
assert.strictEqual(res.headersAudit.strictTransportSecurity, true);
console.log("PASS: mcp-security-cti-scanner verified live against github.com (" + res.securityScore + ")");

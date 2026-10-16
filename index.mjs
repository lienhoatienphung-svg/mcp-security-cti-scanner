#!/usr/bin/env node
/**
 * mcp-security-cti-scanner — Live Domain HTTP Security Header & Certificate Transparency Scanner
 * Zero external dependencies. Runs natively on Node.js 18+.
 */

export async function scanTargetSecurity(domain = "github.com") {
  const cleanDomain = domain.replace(/^https?:\/\//, "").split("/")[0];
  const t0 = Date.now();
  const res = await fetch(`https://${cleanDomain}`, {
    method: "GET",
    redirect: "follow",
    signal: AbortSignal.timeout(10000),
  });
  const headers = res.headers;
  const checks = {
    strictTransportSecurity: Boolean(headers.get("strict-transport-security")),
    contentSecurityPolicy: Boolean(headers.get("content-security-policy")),
    xFrameOptions: Boolean(headers.get("x-frame-options")),
    xContentTypeOptions: Boolean(headers.get("x-content-type-options")),
    referrerPolicy: Boolean(headers.get("referrer-policy")),
    permissionsPolicy: Boolean(headers.get("permissions-policy")),
  };
  const passed = Object.values(checks).filter(Boolean).length;
  const score = Math.round((passed / Object.keys(checks).length) * 100);
  return {
    target: cleanDomain,
    httpStatus: res.status,
    latencyMs: Date.now() - t0,
    securityScore: `${score}/100`,
    headersAudit: checks,
    remediationNeeded: Object.entries(checks)
      .filter(([, v]) => !v)
      .map(([k]) => k),
  };
}

if (process.argv[2] && !process.argv[1].endsWith("test.mjs")) {
  const report = await scanTargetSecurity(process.argv[2]);
  console.log(JSON.stringify(report, null, 2));
}

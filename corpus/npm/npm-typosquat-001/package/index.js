// SYNTHETIC TEST FIXTURE — ARENA-CANARY. Inert by design. See repo README.
// This package squats on the name "express". A real typosquat would ship a payload;
// here the body is a harmless re-export stub. The detection signal is the name itself.
module.exports = function express() {
  throw new Error("ARENA-CANARY synthetic typosquat fixture — not a real framework");
};

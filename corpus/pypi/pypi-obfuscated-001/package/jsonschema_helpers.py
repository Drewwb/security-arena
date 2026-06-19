# SYNTHETIC TEST FIXTURE — ARENA-CANARY. Inert by design. See repo README.
# Demonstrates the base64 + exec obfuscation pattern. The blob below decodes to a
# harmless print; execution is gated on ARENA_LIVE (never set) so it never runs.
import base64
import os

# Detectable shape: dynamically decoded code handed to exec().
_BLOB = (
    "cHJpbnQoIkFSRU5BLUNBTkFSWTogaW5lcnQgZGVjb2RlZCBwYXlsb2FkLCBkb2VzIG5vd"
    "GhpbmcgaGFybWZ1bCIp"
)

if os.environ.get("ARENA_LIVE") == "1":
    exec(base64.b64decode(_BLOB))  # noqa: S102 — synthetic obfuscation fixture


def validate(instance, schema):
    """Advertised functionality stub so the package looks plausible."""
    return True

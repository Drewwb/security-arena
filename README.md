# Supply Chain Scanner Arena

A test corpus + scoring harness for software **supply-chain security scanners**.

Think of it as [EICAR](https://www.eicar.org/download-anti-malware-testfile/) for supply-chain
attacks: a curated set of synthetic, **defanged** malicious packages (plus benign decoys) that you
can point your own scanner at to measure how well it detects known attack techniques — and how often
it false-positives on benign-but-suspicious code.

---

## ⚠️ Safety notice — read first

**Every "malicious" sample in this corpus is INERT.** Each one reproduces the *detectable shape* of a
real attack technique but is deliberately defanged so it cannot cause harm:

- Network destinations use reserved/non-routable ranges (`192.0.2.0/24` per RFC 5737) or `example.com`.
  There are **no real command-and-control endpoints**.
- "Exfiltration" writes to a local canary file; nothing is ever transmitted.
- Reverse shells, droppers, and miners are non-functional, code-shaped stubs.
- Every malicious sample embeds the marker string `ARENA-CANARY` so anyone can confirm at a glance
  that it is a synthetic test fixture.

These are research/QA fixtures for evaluating scanners. Do not adapt them into working malware.

---

## Why this exists

Most scanner vendors' terms prohibit publishing **comparative benchmarks** of their products. This
project deliberately does **not** ship or publish scanner results. It ships:

1. a labeled **corpus** of attack/benign samples, and
2. a **harness** that lets *you* run *your own* scanner privately and score it.

What you do with your own private results is up to you.

## Layout

```
corpus/            labeled samples, one directory per sample
  npm/
  pypi/
taxonomy/          the technique catalog (OpenSSF + MITRE mapped)
arena/             the harness (runner, scorer, adapters)
  adapters/        one module per scanner integration
results/           scan output + scorecards (gitignored)
```

Each sample directory contains the fake package plus a `manifest.yaml` ground-truth label.

## Quick start

```bash
pip install -r requirements.txt

# list the corpus
python -m arena list

# validate every manifest against the schema
python -m arena validate

# run a scanner over the corpus (semgrep shown; needs semgrep installed)
python -m arena run --adapter semgrep

# or: run your scanner yourself, export findings as JSON in our schema, then:
python -m arena run --adapter jsonimport --config findings=path/to/findings.json

# score the most recent run
python -m arena score --adapter semgrep
```

## Adding your scanner

Drop a module in `arena/adapters/`. See [arena/adapters/base.py](arena/adapters/base.py) for the
contract — implement `available()` and `scan(sample)`. The CLI auto-discovers it by name.

## Adding a sample

Copy an existing sample directory, edit the package files, and update `manifest.yaml`. Run
`python -m arena validate` to check it. Malicious samples **must** contain the `ARENA-CANARY` marker.

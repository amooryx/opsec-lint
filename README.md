<div align="center">
  <img src="./banner.svg" alt="opsec-lint" width="800">
</div>

# opsec-lint

> Lint an engagement plan for common OPSEC mistakes

Part of a red-team tooling collection for **authorised** security testing.

## Install

```bash
git clone https://github.com/amooryx/opsec-lint.git
cd opsec-lint
```

## Usage

```bash
python opsec_lint.py <target>
```

When `<target>` is an existing file, opsec-lint scans the UTF-8 (with or without
a byte-order mark) engagement plan
for exact PEM private-key header lines (for example, `-----BEGIN PRIVATE KEY-----`).
This high-confidence check reports line numbers without displaying key contents.
Input files are read-only and limited to 1 MiB. Non-file targets retain the
scaffold behavior.

| Flag | Description |
|---|---|
| `-o, --output` | Write results to a file |
| `-v, --verbose` | Verbose output |
| `-y, --yes` | Skip the authorisation prompt |

For file targets, the command exits with status `1` when a private-key header is
found, `0` when none is found, and `2` when an input or output file cannot be
processed. Run the local regression tests with:

```bash
python -m unittest discover -s tests
```

## Disclaimer

> **Authorised security testing only.** Use this against systems you own or have
> explicit written permission to test. The tool prompts for authorisation before
> acting and is provided for professional engagements, labs, and research.

## Author

**Omar Khalid** — [omareldemery.com](https://omareldemery.com) | [@amooryx](https://github.com/amooryx)

Certifications: OSCP+ · OSCP · CRTP · eWPTX · eCPPT · eCDFP · eCIR · eJPT

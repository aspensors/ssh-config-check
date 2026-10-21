# ssh-config-check

Understand selected OpenSSH server settings before changing them.

An educational, read-only Python tool with line numbers, explanations, text/JSON output and explicit coverage limits. Python 3.11+, standard library only. Runs offline on Linux, macOS and Windows; no SSH server is required to inspect teaching files.

**Early 0.1.0 prototype.** It does not certify a server or replace OpenSSH's own parser. [Русское руководство](docs/GUIDE_RU.md).

## Try it

From this repository:

```bash
python -m ssh_config_check --demo
python -m ssh_config_check --config examples/review.conf
python -m ssh_config_check --config examples/contexts.conf --format json
python -m unittest discover -s tests -v
```

The demo is fictional and never reads host configuration. The program does not execute commands, connect to servers, follow Include paths, modify configuration or restart services. Python may create bytecode caches.

Optional isolated installation:

```bash
python -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/ssh-config-check --demo
```

On Windows use `.venv\\Scripts\\python.exe` and `.venv\\Scripts\\ssh-config-check.exe`. Installation may download build dependencies; runtime has no third-party dependencies.

## Example

```text
[WARN] permitrootlogin (line 2): yes
  Why: Controls authentication as root; restrictions depend on the displayed value.
  Next: Review whether direct root access is needed; verify an alternative administrator login first.
```

WARN means review the observation in your environment. Password authentication can be an MFA factor; keyboard-interactive is not automatically classified as weak. INFO is an observation, not a pass. No security score or automatic fixes.

## Two modes

| Mode | Input | What is assessed |
| --- | --- | --- |
| `--config FILE` | A UTF-8 server configuration | Explicit supported global declarations before the first Match; first value wins |
| `--effective FILE` | Output you previously captured from `sshd -T` | Supported values in that text; the tool cannot verify its origin or context |

Seven scalar settings: PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, PubkeyAuthentication, StrictModes, KbdInteractiveAuthentication and LogLevel.

Other global directives are listed as unassessed. Missing values are UNKNOWN: defaults vary by version and are not assumed. Keywords and supported enum/boolean values are normalized as accepted by OpenSSH (LogLevel is displayed uppercase). A repeated static scalar retains its first value and gets an INFO note; duplicates in effective output produce UNKNOWN. Invalid input never becomes a PASS.

The static parser supports whitespace or equals separators, single/double-quoted values and comments in this subset. Backslash escaping is not implemented. It does not reproduce the whole OpenSSH grammar. Include is not followed. All lines after the first Match (including Match all) are outside global analysis. After a tokenization error, unsupported directive syntax or control characters, later declarations are not assumed to be global. Each Include/Match creates an UNKNOWN observation. A file without these directives is still only partially assessed.

## Let OpenSSH resolve Include and Match

Use your installed OpenSSH to validate a trusted configuration and capture its effective values. Example for a **fictional** connection context:

```bash
sshd -t -f ./sshd_config
sshd -T -f ./sshd_config -C user=demo,host=client.example,addr=192.0.2.10 > effective.txt
python -m ssh_config_check --effective effective.txt
```

These are commands you run manually; privileges, host keys and paths depend on your system. Choose real connection parameters and repeat for each relevant context. Do not treat a single capture as coverage of all users or addresses. The tool never executes directives such as AuthorizedKeysCommand.

## Automation and boundaries

```bash
python -m ssh_config_check --config examples/review.conf --format json
python -m ssh_config_check --config examples/contexts.conf --strict
```

Default exit code is 0 when a report is produced. With `--strict`: 2 if any UNKNOWN exists, otherwise 1 if WARN exists, otherwise 0. Input/argument errors exit 2. Strict 0 still means partial coverage, not a secure server.

JSON contains schema/tool version, mode, source, demo flag, status counts, limitations, unassessed directives and findings with line numbers. Maximum input: 1 MiB, UTF-8. Terminal controls are escaped in text output. File paths and policy values may be private; use fictional fixtures for public examples.

Not checked: running daemon configuration/state, network reachability, keys, algorithm policy, filesystem ownership, PAM, complete authentication chains, SSH client configuration or all syntax errors. Run `sshd -t` for authoritative validation. Tests use synthetic configurations; no live server certification is claimed.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Useful next steps: more version-specific OpenSSH fixtures, integration against real `sshd -T -C` captures and clearer per-context reporting. Changes should keep incomplete observations explicit.

## References

- [OpenSSH sshd_config(5)](https://man.openbsd.org/sshd_config)
- [OpenSSH sshd(8): -t, -T, -C](https://man.openbsd.org/sshd.8)

MIT license. Part of [aspensors' projects](https://github.com/aspensors).

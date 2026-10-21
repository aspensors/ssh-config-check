"""A deliberately limited parser, not an implementation of sshd_config(5)."""
from collections import Counter
from dataclasses import asdict, dataclass
import re
import shlex

MAX_BYTES = 1024 * 1024
BOOL = {"yes", "no"}
# Only these single-valued options are interpreted. Unknown options are inventoried.
VALUES = {
    "permitrootlogin": {"yes", "no", "prohibit-password", "without-password", "forced-commands-only"},
    "passwordauthentication": BOOL,
    "permitemptypasswords": BOOL,
    "pubkeyauthentication": BOOL,
    "strictmodes": BOOL,
    "kbdinteractiveauthentication": BOOL,
    "loglevel": {"QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3"},
}
NOTES = {
    "permitrootlogin": ("Controls authentication as root; restrictions depend on the displayed value.", "Review whether direct root access is needed; verify an alternative administrator login first."),
    "passwordauthentication": ("Controls password authentication; AuthenticationMethods may require it as an MFA factor.", "Review authentication policy, MFA and network exposure before changing access."),
    "permitemptypasswords": ("Controls empty-password authentication, subject to other authentication conditions.", "Review account policy and disable empty passwords where not explicitly required."),
    "pubkeyauthentication": ("Controls public-key authentication; the displayed value is an observation of this option only.", "Review available authentication methods; this alone does not prove a vulnerability."),
    "strictmodes": ("Controls OpenSSH ownership/mode checks for user files; actual permissions are not inspected.", "Review file permissions and any exception to ownership/mode checks."),
    "kbdinteractiveauthentication": ("Keyboard-interactive may provide PAM or MFA; enabled does not imply a weakness.", "Review PAM and AuthenticationMethods together."),
    "loglevel": ("Logging policy affects visibility and may expose extra details at debug levels.", "Review audit requirements and avoid persistent debug logging unless needed."),
}


@dataclass
class Finding:
    check: str
    status: str
    value: str | None
    line: int | None
    explanation: str
    suggestion: str


def analyze(text, *, effective=False, source="provided text"):
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ValueError("Input exceeds the 1 MiB limit")
    findings, options, skipped = [], {}, set()
    global_scope_known = True
    for number, raw in enumerate(text.split("\n"), 1):
        raw = raw.removesuffix("\r")
        if any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in raw):
            findings.append(Finding("syntax", "UNKNOWN", None, number, "Control characters in input.", "Use an unmodified UTF-8 text configuration."))
            global_scope_known = False
            continue
        stripped = raw.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        directive = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*)(?:[ \t]*=[ \t]*|[ \t]+)(.*)", stripped)
        if directive:
            key, arguments = directive.group(1).lower(), directive.group(2)
        elif re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", stripped):
            key, arguments = stripped.lower(), ""
        else:
            findings.append(Finding("syntax", "UNKNOWN", None, number, "Unsupported directive syntax; remaining global scope is uncertain.", "Validate the original file with sshd -t."))
            global_scope_known = False
            continue
        # shlex supplies quoted-value handling for our supported subset only.
        try:
            lexer = shlex.shlex(arguments, posix=True)
            lexer.whitespace_split = True
            lexer.commenters = "#"
            lexer.quotes = "\"'"
            lexer.escape = ""
            args = list(lexer)
        except ValueError:
            findings.append(Finding("syntax", "UNKNOWN", None, number, "Unclosed quote or unsupported escaping.", "Validate the original file with sshd -t."))
            global_scope_known = False
            continue
        if key in {"include", "match"}:
            findings.append(Finding(key, "UNKNOWN", " ".join(args), number,
                "Include files and Match contexts are not evaluated by this offline parser.",
                "Capture sshd -T -f FILE -C user=USER,host=HOST,addr=IP for each relevant connection context."))
            if key == "match":
                global_scope_known = False
            continue
        if not global_scope_known:
            continue
        if key not in VALUES:
            skipped.add(key)
            continue
        args = [value.upper() if key == "loglevel" else value.lower() for value in args]
        if len(args) != 1 or args[0] not in VALUES[key]:
            findings.append(Finding(key, "UNKNOWN", " ".join(args), number, "Unsupported value or syntax.", "Validate with your installed OpenSSH version using sshd -t."))
            # Never use a later declaration to mask an invalid first value.
            options.setdefault(key, (None, number))
            continue
        if key in options:
            # sshd -T output should not contain duplicate supported scalar options.
            findings.append(Finding("duplicate", "UNKNOWN" if effective else "INFO", key, number,
                "Repeated supported option; the first global declaration is retained.",
                "Review directive order; use authentic sshd -T output to resolve effective values."))
        else:
            options[key] = (args[0], number)
    for key in VALUES:
        value, line = options.get(key, (None, None))
        why, next_step = NOTES[key]
        if value is None:
            findings.append(Finding(key, "UNKNOWN", None, line, "No interpretable global value; version-dependent defaults are not assumed.", "Capture sshd -T output for the relevant configuration and context."))
            continue
        review = ((key == "permitrootlogin" and value == "yes") or
                  (key in {"passwordauthentication", "permitemptypasswords"} and value == "yes") or
                  (key in {"pubkeyauthentication", "strictmodes"} and value == "no") or
                  (key == "loglevel" and value in {"QUIET", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3"}))
        findings.append(Finding(key, "WARN" if review else "INFO", value, line, why, next_step))
    return {
        "schema_version": 1, "source": source, "mode": "effective-output" if effective else "static-global",
        "coverage": "partial", "unassessed_directives": sorted(skipped),
        "limitations": [
            "Only seven explicit scalar options are assessed. No security score or PASS verdict.",
            "Static mode does not resolve Include, Match, defaults, command-line overrides or all OpenSSH syntax.",
            "Effective-output mode trusts the supplied text; its origin and connection context are not verified.",
            "A WARN is a review prompt, not proof of a vulnerability. INFO is not proof of security.",
            "Running service state, actual access, PAM, keys, algorithms and filesystem permissions are not checked.",
        ],
        "summary": dict(Counter(item.status for item in findings)),
        "findings": [asdict(item) for item in findings],
    }


def read_input(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Input exceeds the 1 MiB limit")
    return raw.decode("utf-8")

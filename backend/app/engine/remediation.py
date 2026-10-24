"""Remediation safety layer.

LLM output is NEVER executed as-is. Every script must:
  * contain exactly 3 command lines,
  * use only allow-listed command shapes (iptables DROP/REJECT rule, logger),
  * reference only the alert's own IP address.
Execution uses shlex + subprocess without a shell, and defaults to simulate mode.
"""
import re
import shlex
import subprocess

from app.config import settings
from app.database import db
from app.schemas.models import AlertPayload, QuarantineResult

_IPT_RE = re.compile(
    r"^iptables -I (?:INPUT|OUTPUT|FORWARD) -[sd] (\d{1,3}(?:\.\d{1,3}){3}) -j (?:DROP|REJECT)$"
)
_LOG_RE = re.compile(r'^logger -t civicshield "[A-Za-z0-9 _.:()/\-]{1,120}"$')
_CLEAN_RE = re.compile(r"[^A-Za-z0-9 _.\-]")


class RemediationRejected(Exception):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


def normalize_script(raw) -> str:
    """Strip code fences, shebangs, comments and blank lines from model output."""
    if isinstance(raw, (list, tuple)):
        raw = "\n".join(str(x) for x in raw)
    text = str(raw or "").replace("\r", "").replace("\\n", "\n")
    text = re.sub(r"```(?:bash|sh)?", "", text)
    lines = [ln.strip() for ln in text.split("\n")]
    return "\n".join(ln for ln in lines if ln and not ln.startswith("#"))


def validate_script(script: str, expected_ip: str) -> list[str]:
    """Return a list of problems; an empty list means the script is safe to run."""
    problems: list[str] = []
    lines = script.split("\n") if script else []
    if len(lines) != 3:
        problems.append(f"expected exactly 3 command lines, got {len(lines)}")
    isolation_rules = 0
    for i, line in enumerate(lines, 1):
        match = _IPT_RE.match(line)
        if match:
            isolation_rules += 1
            if match.group(1) != expected_ip:
                problems.append(f"line {i}: IP {match.group(1)} does not match target {expected_ip}")
        elif not _LOG_RE.match(line):
            problems.append(f"line {i}: command is not in the allow-list")
    if isolation_rules == 0:
        problems.append("no iptables isolation rule present")
    return problems


def build_default_script(ip: str, entity_id: str, threat_type: str) -> str:
    """Deterministic 3-line isolation script (used when the LLM output is rejected/unavailable)."""
    note = _CLEAN_RE.sub("", f"Quarantined {entity_id} {threat_type}")[:100]
    return (
        f"iptables -I INPUT -s {ip} -j DROP\n"
        f"iptables -I OUTPUT -d {ip} -j DROP\n"
        f'logger -t civicshield "{note}"'
    )


def execute_remediation(alert: AlertPayload) -> QuarantineResult:
    """Re-validate and run the alert's remediation script, then mark it quarantined."""
    if alert.triage is None:
        raise RemediationRejected(["alert has not been triaged yet"])

    script = normalize_script(alert.triage.remediation_script)
    problems = validate_script(script, alert.ip_address)
    if problems:
        raise RemediationRejected(problems)

    commands = script.split("\n")
    output: list[str] = []
    ok = True

    if settings.remediation_mode == "live":
        # Must run on the edge gateway with sufficient privileges (e.g. CAP_NET_ADMIN).
        for line in commands:
            try:
                proc = subprocess.run(shlex.split(line), capture_output=True, text=True, timeout=10, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                output.append(f"$ {line} -> ERROR {type(exc).__name__}")
                ok = False
                break
            output.append(f"$ {line} -> rc={proc.returncode} {proc.stderr.strip()}".rstrip())
            if proc.returncode != 0:
                ok = False
                break
    else:
        output = [f"[SIMULATED] $ {line}" for line in commands]

    if ok:
        db.mark_quarantined(alert.alert_id, output)

    return QuarantineResult(
        alert_id=alert.alert_id,
        executed=ok,
        mode=settings.remediation_mode,
        commands=commands,
        output=output,
        status=db.get_alert(alert.alert_id).status,
    )
"""KOPPA stdlib: report — finding collection and formatted output."""
import json, datetime, re


_SEV_COLOR = {
    "critical": "\033[91m",  # red
    "high":     "\033[91m",
    "medium":   "\033[93m",  # yellow
    "low":      "\033[96m",  # cyan
    "info":     "\033[94m",  # blue
}
_RESET = "\033[0m"
_BOLD  = "\033[1m"
_GREEN = "\033[92m"


class Finding:
    def __init__(self, title, severity, detail, url="", evidence=""):
        self.title    = title
        self.severity = severity.lower()
        self.detail   = detail
        self.url      = url
        self.evidence = evidence
        self.ts       = datetime.datetime.utcnow().isoformat()

    def __repr__(self):
        col = _SEV_COLOR.get(self.severity, "")
        return f"{col}[{self.severity.upper()}]{_RESET} {self.title}: {self.detail}"

    def to_dict(self):
        return {
            "title":    self.title,
            "severity": self.severity,
            "detail":   self.detail,
            "url":      self.url,
            "evidence": self.evidence,
            "timestamp":self.ts,
        }


def finding(title, severity="info", detail="", url="", evidence=""):
    return Finding(title, severity, detail, url, evidence)


def terminal(findings, title="Scan Report"):
    if not findings:
        return f"{_BOLD}[Report]{_RESET} No findings."
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines = [
        "",
        f"{_BOLD}{'='*60}{_RESET}",
        f"{_BOLD}  KOPPA {title}{_RESET}",
        f"  {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC",
        f"{_BOLD}{'='*60}{_RESET}",
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        grp = [f for f in findings if f.severity == sev]
        if not grp:
            continue
        col = _SEV_COLOR.get(sev, "")
        lines.append(f"\n{col}{_BOLD}[{sev.upper()}] ({len(grp)}){_RESET}")
        for f in grp:
            lines.append(f"  {col}▸{_RESET} {f.title}")
            if f.detail:
                lines.append(f"    {f.detail}")
            if f.url:
                lines.append(f"    URL: {f.url}")

    lines += [
        f"\n{_BOLD}Summary:{_RESET}",
        "  " + "  ".join(
            f"{_SEV_COLOR.get(s,'')}{s.upper()}: {n}{_RESET}"
            for s, n in counts.items()
        ),
        f"{_BOLD}{'='*60}{_RESET}",
    ]
    return "\n".join(lines)


def json_export(findings):
    return json.dumps([f.to_dict() for f in findings], indent=2)


def markdown(findings, title="Pentest Report"):
    lines = [f"# {title}", f"*{datetime.datetime.utcnow().strftime('%Y-%m-%d')}*", ""]
    for sev in ["critical", "high", "medium", "low", "info"]:
        grp = [f for f in findings if f.severity == sev]
        if not grp:
            continue
        lines.append(f"## {sev.upper()} ({len(grp)})")
        for f in grp:
            lines.append(f"- **{f.title}**: {f.detail}")
            if f.url:
                lines.append(f"  - URL: `{f.url}`")
        lines.append("")
    return "\n".join(lines)


def save(findings, path, fmt="json"):
    """Save findings to file."""
    if fmt == "json":
        content = json_export(findings)
    elif fmt == "md":
        content = markdown(findings)
    else:
        content = terminal(findings)
    import os
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    return path

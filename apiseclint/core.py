"""Core engine for APISECLINT.

Parses an OpenAPI spec (JSON, or a small YAML subset) and runs a set of
security rules over it. Each rule yields zero or more Finding objects.

Standard library only.
"""
from __future__ import annotations

import html as _html
import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

    @classmethod
    def rank(cls, sev: str) -> int:
        return cls.ORDER.get(sev, 99)


# Severities at or above this rank (i.e. <= threshold) cause a non-zero exit.
FAIL_AT = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    location: str
    detail: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LintReport:
    source: str
    spec_title: str
    spec_version: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def counts(self) -> Dict[str, int]:
        out = {s: 0 for s in Severity.ORDER}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    @property
    def failed(self) -> bool:
        return any(f.severity in FAIL_AT for f in self.findings)

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (Severity.rank(f.severity), f.rule_id))


HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")

# Heuristics for property/parameter names that look like sensitive data.
SENSITIVE_FIELD_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|apikey|ssn|social_?security|"
    r"credit_?card|card_?number|cvv|cvc|private_?key|access_?key|client_?secret|"
    r"auth)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Spec loading (JSON + minimal YAML subset)
# ---------------------------------------------------------------------------

def load_spec(text: str) -> Dict[str, Any]:
    """Load an OpenAPI spec from text. Tries JSON first, then a minimal YAML
    parser sufficient for typical flow-style-free specs."""
    text = text.lstrip("﻿")
    stripped = text.lstrip()
    if stripped.startswith("{"):
        return json.loads(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    return _parse_min_yaml(text)


def _coerce_scalar(val: str) -> Any:
    v = val.strip()
    if v == "" or v == "~" or v.lower() == "null":
        return None
    if v.lower() == "true":
        return True
    if v.lower() == "false":
        return False
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    if re.fullmatch(r"-?\d+\.\d+", v):
        return float(v)
    # Inline flow list: [a, b, c]
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        if not inner:
            return []
        return [_coerce_scalar(x) for x in _split_flow(inner)]
    return v


def _split_flow(inner: str) -> List[str]:
    parts, depth, cur = [], 0, ""
    for ch in inner:
        if ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


def _parse_min_yaml(text: str) -> Dict[str, Any]:
    """Indentation-based YAML subset: nested maps, simple list items, scalars.
    Sufficient for hand-written OpenAPI specs. Raises ValueError otherwise."""
    lines = []
    for raw in text.splitlines():
        # strip comments not inside quotes (best-effort)
        if "#" in raw:
            in_q = None
            buf = ""
            for ch in raw:
                if ch in ("'", '"'):
                    in_q = None if in_q == ch else (in_q or ch)
                if ch == "#" and in_q is None:
                    break
                buf += ch
            raw = buf
        if raw.strip() == "":
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((indent, raw.strip()))

    pos = 0

    def parse_block(min_indent: int):
        nonlocal pos
        # Decide list vs map by first line
        if pos >= len(lines):
            return None
        indent, content = lines[pos]
        is_list = content.startswith("- ")
        container: Any = [] if is_list else {}
        while pos < len(lines):
            indent, content = lines[pos]
            if indent < min_indent:
                break
            if isinstance(container, list) != content.startswith("- "):
                if indent == min_indent:
                    raise ValueError("inconsistent YAML block")
                break
            if content.startswith("- "):
                pos += 1
                item = content[2:].strip()
                if item == "":
                    container.append(parse_block(indent + 1))
                elif ":" in item and not item.startswith(("'", '"')):
                    # list of inline maps: "- key: val"
                    k, _, v = item.partition(":")
                    d = {k.strip(): _coerce_scalar(v)}
                    container.append(d)
                else:
                    container.append(_coerce_scalar(item))
            else:
                key, sep, val = content.partition(":")
                if not sep:
                    raise ValueError(f"bad YAML line: {content!r}")
                key = key.strip().strip('"').strip("'")
                pos += 1
                if val.strip() == "":
                    if pos < len(lines) and lines[pos][0] > indent:
                        container[key] = parse_block(indent + 1)
                    else:
                        container[key] = None
                else:
                    container[key] = _coerce_scalar(val)
        return container

    result = parse_block(0)
    if not isinstance(result, dict):
        raise ValueError("spec root is not a mapping")
    return result


# ---------------------------------------------------------------------------
# Spec helpers
# ---------------------------------------------------------------------------

def _is_openapi3(spec: Dict[str, Any]) -> bool:
    return str(spec.get("openapi", "")).startswith("3")


def _security_schemes(spec: Dict[str, Any]) -> Dict[str, Any]:
    if _is_openapi3(spec):
        return (spec.get("components") or {}).get("securitySchemes") or {}
    return spec.get("securityDefinitions") or {}


def _iter_operations(spec: Dict[str, Any]) -> Iterable[Tuple[str, str, Dict[str, Any]]]:
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in HTTP_METHODS:
            op = item.get(method)
            if isinstance(op, dict):
                yield path, method.upper(), op


def _walk(node: Any, path: str = "") -> Iterable[Tuple[str, Any]]:
    yield path, node
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, f"{path}.{k}" if path else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}[{i}]")


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def _rule_global_security(spec, schemes) -> List[Finding]:
    out: List[Finding] = []
    global_sec = spec.get("security")
    if not schemes:
        out.append(Finding(
            "AUTHN001", "No security schemes defined", Severity.CRITICAL,
            "components.securitySchemes",
            "The spec declares no authentication schemes at all.",
            "Define at least one securityScheme (OAuth2, OpenID Connect, or HTTP "
            "bearer) and reference it from operations.",
        ))
    if global_sec is None:
        out.append(Finding(
            "AUTHN002", "No global security requirement", Severity.MEDIUM,
            "security",
            "No top-level 'security' is set, so unprotected operations are the default.",
            "Set a global 'security' requirement and override per-operation only "
            "where anonymous access is intentional.",
        ))
    return out


def _rule_operation_authz(spec, schemes) -> List[Finding]:
    out: List[Finding] = []
    has_global = bool(spec.get("security"))
    for path, method, op in _iter_operations(spec):
        loc = f"paths.{path}.{method.lower()}"
        op_sec = op.get("security", None)
        # security: [] explicitly disables auth for the operation
        if op_sec == []:
            sev = Severity.HIGH if method in ("POST", "PUT", "PATCH", "DELETE") else Severity.MEDIUM
            out.append(Finding(
                "AUTHZ001", "Operation explicitly disables authentication", sev, loc,
                f"{method} {path} sets 'security: []', allowing anonymous access.",
                "Remove the empty security override unless this endpoint is "
                "intentionally public; document why if it is.",
            ))
        elif op_sec is None and not has_global:
            sev = Severity.HIGH if method in ("POST", "PUT", "PATCH", "DELETE") else Severity.MEDIUM
            out.append(Finding(
                "AUTHZ002", "Operation has no authentication", sev, loc,
                f"{method} {path} inherits no security and no global default exists.",
                "Attach a 'security' requirement to this operation or define a "
                "global default.",
            ))
        # Detect write ops without scope-bearing requirement
        if op_sec and method in ("POST", "PUT", "PATCH", "DELETE"):
            if all(not v for req in op_sec if isinstance(req, dict) for v in req.values()):
                out.append(Finding(
                    "AUTHZ003", "Write operation lacks granular scopes", Severity.LOW, loc,
                    f"{method} {path} requires auth but no OAuth2/OIDC scopes.",
                    "Require explicit scopes for state-changing operations to enforce "
                    "least privilege.",
                ))
    return out


def _rule_weak_schemes(spec, schemes) -> List[Finding]:
    out: List[Finding] = []
    for name, sc in (schemes or {}).items():
        if not isinstance(sc, dict):
            continue
        loc = f"securitySchemes.{name}"
        typ = (sc.get("type") or "").lower()
        scheme = (sc.get("scheme") or "").lower()
        if typ == "http" and scheme == "basic":
            out.append(Finding(
                "AUTHN003", "HTTP Basic authentication", Severity.MEDIUM, loc,
                f"Scheme '{name}' uses HTTP Basic, sending reusable credentials on "
                "every request.",
                "Prefer short-lived bearer tokens (OAuth2/OIDC) over Basic auth.",
            ))
        if typ == "apikey":
            loc_in = (sc.get("in") or "").lower()
            sev = Severity.HIGH if loc_in == "query" else Severity.MEDIUM
            extra = " in the query string (logged by proxies/servers)" if loc_in == "query" else ""
            out.append(Finding(
                "AUTHN004", "API key authentication", sev, loc,
                f"Scheme '{name}' is a static API key{extra}.",
                "Use API keys only as a coarse gate; move secrets to headers and "
                "prefer rotating OAuth2 tokens for user-level authz.",
            ))
        if typ == "oauth2":
            flows = sc.get("flows") or {}
            if "implicit" in flows or (sc.get("flow") == "implicit"):
                out.append(Finding(
                    "AUTHN005", "OAuth2 implicit flow", Severity.HIGH, loc,
                    f"Scheme '{name}' uses the deprecated OAuth2 implicit flow.",
                    "Migrate to authorization code flow with PKCE.",
                ))
    return out


def _rule_transport(spec, schemes) -> List[Finding]:
    out: List[Finding] = []
    if _is_openapi3(spec):
        for i, srv in enumerate(spec.get("servers") or []):
            if isinstance(srv, dict):
                url = str(srv.get("url", ""))
                if url.startswith("http://"):
                    out.append(Finding(
                        "TLS001", "Server uses cleartext HTTP", Severity.HIGH,
                        f"servers[{i}].url",
                        f"Server URL '{url}' is plaintext HTTP.",
                        "Serve the API over HTTPS only.",
                    ))
    else:
        schemes_list = spec.get("schemes") or []
        if "http" in [str(s).lower() for s in schemes_list]:
            out.append(Finding(
                "TLS001", "API advertises cleartext HTTP", Severity.HIGH, "schemes",
                "The 'schemes' list includes 'http'.",
                "Restrict 'schemes' to ['https'].",
            ))
    return out


def _rule_rate_limit(spec, schemes) -> List[Finding]:
    out: List[Finding] = []
    rl_header_re = re.compile(r"(x-)?rate-?limit|retry-after|x-ratelimit", re.IGNORECASE)
    seen_rl = False
    for _, node in _walk(spec):
        if isinstance(node, dict):
            for k in node.keys():
                if isinstance(k, str) and rl_header_re.search(k):
                    seen_rl = True
                    break
        if seen_rl:
            break
    has_429 = False
    for path, method, op in _iter_operations(spec):
        responses = op.get("responses") or {}
        if "429" in {str(c) for c in responses.keys()}:
            has_429 = True
            break
    if not (seen_rl or has_429):
        out.append(Finding(
            "RATE001", "No rate limiting indicated", Severity.MEDIUM, "paths.*",
            "No 429 responses or RateLimit/Retry-After headers are documented "
            "anywhere in the spec.",
            "Document 429 responses and RateLimit/Retry-After headers, and enforce "
            "throttling at the gateway.",
        ))
    return out


def _rule_data_exposure(spec, schemes) -> List[Finding]:
    out: List[Finding] = []
    for dotted, node in _walk(spec):
        if not isinstance(node, dict):
            continue
        props = node.get("properties")
        if isinstance(props, dict):
            for pname, pdef in props.items():
                if isinstance(pname, str) and SENSITIVE_FIELD_RE.search(pname):
                    is_write_only = isinstance(pdef, dict) and pdef.get("writeOnly") is True
                    if not is_write_only:
                        out.append(Finding(
                            "DATA001", "Sensitive field may be exposed in responses",
                            Severity.HIGH, f"{dotted}.properties.{pname}",
                            f"Property '{pname}' looks sensitive but is not marked writeOnly.",
                            "Mark secret/credential fields as writeOnly:true so they are "
                            "never serialized in responses, or remove them from output schemas.",
                        ))
    return out


def _rule_additional_properties(spec, schemes) -> List[Finding]:
    out: List[Finding] = []
    for path, method, op in _iter_operations(spec):
        body = op.get("requestBody")
        schemas: List[Tuple[str, Any]] = []
        if isinstance(body, dict):
            for ct, media in (body.get("content") or {}).items():
                if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                    schemas.append((f"requestBody.content.{ct}", media["schema"]))
        # swagger 2 body params
        for p in op.get("parameters") or []:
            if isinstance(p, dict) and p.get("in") == "body" and isinstance(p.get("schema"), dict):
                schemas.append(("parameters[body]", p["schema"]))
        for sloc, schema in schemas:
            if schema.get("type") == "object" or "properties" in schema:
                if "additionalProperties" not in schema:
                    out.append(Finding(
                        "MASS001", "Request body allows mass assignment", Severity.MEDIUM,
                        f"paths.{path}.{method.lower()}.{sloc}",
                        f"{method} {path} request schema does not set "
                        "additionalProperties:false.",
                        "Set additionalProperties:false on input schemas to block "
                        "unexpected/over-posted fields (mass assignment).",
                    ))
    return out


def _rule_unbounded_collections(spec, schemes) -> List[Finding]:
    out: List[Finding] = []
    pag_re = re.compile(r"(page|limit|offset|cursor|per_?page|size)", re.IGNORECASE)
    for path, method, op in _iter_operations(spec):
        if method != "GET":
            continue
        params = op.get("parameters") or []
        names = [str(p.get("name", "")) for p in params if isinstance(p, dict)]
        # only flag collection-style paths (plural / no trailing id param)
        looks_collection = not re.search(r"\{[^}]+\}$", path.rstrip("/"))
        if looks_collection and not any(pag_re.search(n) for n in names):
            out.append(Finding(
                "DOS001", "Collection endpoint has no pagination", Severity.LOW,
                f"paths.{path}.get",
                f"GET {path} appears to list a collection but exposes no "
                "page/limit/offset/cursor parameter.",
                "Add pagination parameters and a server-enforced maximum page size "
                "to prevent resource-exhaustion.",
            ))
    return out


def _rule_error_responses(spec, schemes) -> List[Finding]:
    out: List[Finding] = []
    for path, method, op in _iter_operations(spec):
        responses = {str(c) for c in (op.get("responses") or {}).keys()}
        loc = f"paths.{path}.{method.lower()}"
        if "401" not in responses and "default" not in responses:
            out.append(Finding(
                "DOC001", "No 401 Unauthorized response documented", Severity.LOW, loc,
                f"{method} {path} documents no 401 response.",
                "Document 401 (and 403) responses so clients handle auth failures "
                "and reviewers can verify protection.",
            ))
    return out


RULES = [
    _rule_global_security,
    _rule_operation_authz,
    _rule_weak_schemes,
    _rule_transport,
    _rule_rate_limit,
    _rule_data_exposure,
    _rule_additional_properties,
    _rule_unbounded_collections,
    _rule_error_responses,
]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def lint_spec(spec: Dict[str, Any], source: str = "<spec>") -> LintReport:
    info = spec.get("info") or {}
    report = LintReport(
        source=source,
        spec_title=str(info.get("title", "Untitled API")),
        spec_version=str(info.get("version", "?")),
    )
    schemes = _security_schemes(spec)
    for rule in RULES:
        try:
            report.findings.extend(rule(spec, schemes))
        except Exception as exc:  # a buggy rule must not crash the whole lint
            report.findings.append(Finding(
                "ENGINE000", f"Rule {rule.__name__} errored", Severity.INFO, "engine",
                str(exc), "Report this as a bug.",
            ))
    return report


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def render_table(report: LintReport) -> str:
    lines: List[str] = []
    lines.append(f"APISECLINT report for: {report.spec_title} v{report.spec_version}")
    lines.append(f"Source: {report.source}")
    lines.append("")
    c = report.counts
    summary = "  ".join(
        f"{s.upper()}={c.get(s, 0)}"
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
    )
    lines.append(f"Summary: {summary}  (total={len(report.findings)})")
    lines.append("")
    if not report.findings:
        lines.append("No findings. Spec passes all checks.")
        return "\n".join(lines)
    hdr = f"{'SEV':<9} {'RULE':<10} {'LOCATION':<40} TITLE"
    lines.append(hdr)
    lines.append("-" * len(hdr))
    for f in report.sorted_findings():
        loc = (f.location[:37] + "...") if len(f.location) > 40 else f.location
        lines.append(f"{f.severity.upper():<9} {f.rule_id:<10} {loc:<40} {f.title}")
    lines.append("")
    lines.append("Details:")
    for f in report.sorted_findings():
        lines.append(f"  [{f.severity.upper()}] {f.rule_id} @ {f.location}")
        lines.append(f"      {f.detail}")
        lines.append(f"      Fix: {f.remediation}")
    return "\n".join(lines)


def render_json(report: LintReport) -> str:
    payload = {
        "tool": "apiseclint",
        "source": report.source,
        "spec": {"title": report.spec_title, "version": report.spec_version},
        "summary": report.counts,
        "total": len(report.findings),
        "failed": report.failed,
        "findings": [f.to_dict() for f in report.sorted_findings()],
    }
    return json.dumps(payload, indent=2)


_SEV_COLOR = {
    Severity.CRITICAL: "#7b1d1d",
    Severity.HIGH: "#c0392b",
    Severity.MEDIUM: "#d68910",
    Severity.LOW: "#2471a3",
    Severity.INFO: "#566573",
}


def render_html(report: LintReport) -> str:
    e = _html.escape
    c = report.counts
    rows = []
    for f in report.sorted_findings():
        color = _SEV_COLOR.get(f.severity, "#566573")
        rows.append(
            "<tr>"
            f"<td><span class='badge' style='background:{color}'>{e(f.severity.upper())}</span></td>"
            f"<td class='mono'>{e(f.rule_id)}</td>"
            f"<td><strong>{e(f.title)}</strong><div class='loc mono'>{e(f.location)}</div>"
            f"<div class='detail'>{e(f.detail)}</div>"
            f"<div class='fix'>Fix: {e(f.remediation)}</div></td>"
            "</tr>"
        )
    rows_html = "\n".join(rows) if rows else (
        "<tr><td colspan='3' class='ok'>No findings — spec passes all checks.</td></tr>"
    )
    chips = []
    for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        chips.append(
            f"<span class='chip' style='border-color:{_SEV_COLOR[s]};color:{_SEV_COLOR[s]}'>"
            f"{s.upper()}: <b>{c.get(s, 0)}</b></span>"
        )
    status = "FAIL" if report.failed else "PASS"
    status_color = "#c0392b" if report.failed else "#1e8449"
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>APISECLINT — {e(report.spec_title)}</title>
<style>
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
       margin: 0; background: #f4f6f8; color: #1c2833; }}
header {{ background: #1c2833; color: #fff; padding: 24px 32px; }}
header h1 {{ margin: 0 0 4px; font-size: 20px; }}
header .sub {{ color: #aeb6bf; font-size: 13px; }}
.status {{ display:inline-block; margin-left: 12px; padding: 2px 12px; border-radius: 4px;
          background: {status_color}; font-weight: 700; font-size: 13px; }}
.wrap {{ max-width: 1000px; margin: 0 auto; padding: 24px 32px; }}
.chips {{ margin: 0 0 20px; }}
.chip {{ display:inline-block; padding: 4px 12px; margin: 4px 8px 4px 0;
        border: 2px solid #ccc; border-radius: 16px; font-size: 13px; }}
table {{ width: 100%; border-collapse: collapse; background: #fff;
        box-shadow: 0 1px 3px rgba(0,0,0,.12); border-radius: 6px; overflow: hidden; }}
th {{ text-align: left; background: #eaeded; padding: 10px 14px; font-size: 12px;
     text-transform: uppercase; letter-spacing: .04em; color: #566573; }}
td {{ padding: 12px 14px; border-top: 1px solid #eaeded; vertical-align: top; }}
.badge {{ color:#fff; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
.mono {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; }}
.loc {{ color:#7f8c8d; margin-top: 2px; }}
.detail {{ margin-top: 6px; font-size: 13px; }}
.fix {{ margin-top: 6px; font-size: 13px; color:#1e8449; }}
.ok {{ text-align:center; color:#1e8449; padding: 24px; }}
footer {{ text-align:center; color:#909497; font-size:12px; padding: 24px; }}
</style></head>
<body>
<header>
  <h1>APISECLINT report <span class="status">{status}</span></h1>
  <div class="sub">{e(report.spec_title)} v{e(report.spec_version)} &middot; source: {e(report.source)}
   &middot; {len(report.findings)} finding(s)</div>
</header>
<div class="wrap">
  <div class="chips">{''.join(chips)}</div>
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Finding</th></tr></thead>
    <tbody>
{rows_html}
    </tbody>
  </table>
</div>
<footer>Generated by APISECLINT 1.0.0 — static OpenAPI security linter (stdlib only)</footer>
</body></html>"""

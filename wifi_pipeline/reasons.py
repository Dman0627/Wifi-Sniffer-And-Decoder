from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Reason:
    code: str
    kind: str
    summary: str
    detail: str = ""
    remediation: str = ""


def make_blocker(code: str, summary: str, detail: str = "", remediation: str = "") -> Reason:
    return Reason(code=code, kind="blocker", summary=summary, detail=detail, remediation=remediation)


def make_limitation(code: str, summary: str, detail: str = "", remediation: str = "") -> Reason:
    return Reason(code=code, kind="limitation", summary=summary, detail=detail, remediation=remediation)


def make_context(code: str, summary: str, detail: str = "", remediation: str = "") -> Reason:
    return Reason(code=code, kind="context", summary=summary, detail=detail, remediation=remediation)

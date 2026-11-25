"""Read-only findings presentation. Never changes saved assessment evidence.

Only identical records within one assessment are collapsed. Similar titles,
different sources, confidence, evidence or remediation are not proof of the
same issue. No exploitability inference or confidence promotion is performed.
"""
from dataclasses import dataclass
import json

from .evidence import sanitize

RISK_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
PRIORITY = {
    'critical': ('Review immediately', 'Potentially severe impact. Confirm the evidence promptly and involve the responsible owner.'),
    'high': ('Review promptly', 'Potentially significant impact. Confirm the finding and prioritize an appropriate fix.'),
    'medium': ('Plan a fix', 'Potential impact depends on the affected system and its use. Review context before scheduling remediation.'),
    'low': ('Improve configuration', 'A lower reported risk or defense-in-depth improvement. Review during routine maintenance.'),
    'info': ('Review context', 'An observation for awareness; it is not necessarily a vulnerability.'),
    'unknown': ('Needs classification', 'No recognized risk rating. Review the evidence before assigning priority.'),
}
CONFIDENCE = {
    'high': 'Strong reported evidence; not proof of exploitability.',
    'medium': 'An observation that needs contextual review.',
    'low': 'An indicator that needs independent confirmation.',
    'unknown': 'No confidence level was recorded.',
}


@dataclass(frozen=True)
class FindingView:
    index: int
    finding: dict
    occurrences: int


def finding_views(result):
    """Return priority-ordered views with original indices and exact repeat counts."""
    grouped = {}
    for index, finding in enumerate(result.get('findings', [])):
        # Include every original field to avoid combining distinct locations or metadata.
        key = json.dumps(finding, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
        if key in grouped:
            original, count, record = grouped[key]
            grouped[key] = (original, count + 1, record)
        else:
            grouped[key] = (index, 1, finding)
    views = [FindingView(index, sanitize(record), count)
             for index, count, record in grouped.values()]
    return sorted(views, key=lambda v: RISK_ORDER.get(v.finding.get('severity', '').lower(), 5))


def confidence_note(finding):
    confidence = finding.get('confidence', 'unknown').lower()
    return CONFIDENCE.get(confidence, CONFIDENCE['unknown'])


def priority_note(finding):
    """Display guidance from the reported rating, without rescoring evidence."""
    return PRIORITY.get(finding.get('severity', '').lower(), PRIORITY['unknown'])


def findings_summary(result):
    views = finding_views(result)
    counts = {risk: 0 for risk in (*RISK_ORDER, 'unknown')}
    for view in views:
        risk = view.finding.get('severity', '').lower()
        counts[risk if risk in RISK_ORDER else 'unknown'] += 1
    return {'observations': len(result.get('findings', [])),
            'distinct': len(views), 'exact_repeats': sum(v.occurrences - 1 for v in views),
            'severity': counts}


def finding_detail(view):
    f = view.finding
    priority, explanation = priority_note(f)
    return (f"{f['title']}\n\nRISK: {f['severity'].upper()}\n"
            f"PRIORITY: {priority} — {explanation}\n"
            f"CONFIDENCE: {f.get('confidence', 'unknown')} — {confidence_note(f)}\n"
            f"SOURCE: {f.get('source', 'legacy')} | ID: {f['id']}\n"
            f"IDENTICAL OBSERVATIONS: {view.occurrences}\n\n"
            f"OBSERVED EVIDENCE\n{f['evidence']}\n\n"
            f"RECOMMENDED REMEDIATION\n{f['remediation']}\n\n"
            "After applying the fix, retest the same authorized scope and profile. "
            "An absent finding alone does not establish that the issue is resolved.")

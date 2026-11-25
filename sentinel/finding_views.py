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


# Explain possible consequences without inferring successful exploitation.
IMPACT = {
    'HTTP': 'Traffic on this URL is not encrypted. Sensitive information could be exposed in transit; no interception was tested.',
    'HSTS': 'Browsers may lack an instruction to insist on HTTPS. This is a missing protection, not proof that a connection was intercepted.',
    'CSP': 'A browser protection against some injected scripts is missing. This does not establish that a script can be injected.',
    'FRAME': 'A page might be embeddable in another site. Whether a visitor can be tricked into an unintended action has not been tested.',
    'NOSNIFF': 'A browser protection against unexpected content interpretation is missing. No script execution was tested.',
    'DISCLOSURE': 'Server identification can help someone learn about software in use. This alone does not establish a vulnerable version or access.',
    'TLS_VERIFY': 'The connection could not be trusted by this computer. This may reflect a certificate or configuration problem; interception was not demonstrated.',
    'CORS_CREDENTIAL_REFLECTION': 'The cross-origin response policy may allow untrusted sites to read credentialed responses. Only anonymous requests were tested, not access to private information.',
    'CORS_ORIGIN_REFLECTION': 'The server allowed both synthetic origins. Some public resources intentionally allow cross-origin access; private information was not tested.',
    'CORS_WILDCARD': 'Other websites may read permitted public responses. A wildcard by itself does not allow credentialed browser requests.',
    'CORS_CONFLICT': 'The advertised settings conflict under browser rules. This is not evidence that a private response can be read.',
}


def impact_note(finding):
    return IMPACT.get(finding.get('id'),
                      'Review the observed evidence and the intended behavior of this service. '
                      'This finding alone does not establish that anyone gained access.')

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
            f"WHY THIS MATTERS\n{impact_note(f)}\n\n"
            f"OBSERVED EVIDENCE\n{f['evidence']}\n\n"
            f"RECOMMENDED REMEDIATION\n{f['remediation']}\n\n"
            "After applying the fix, retest the same authorized scope and profile. "
            "An absent finding alone does not establish that the issue is resolved.")

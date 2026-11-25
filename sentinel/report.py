"""Self-contained, read-only HTML assessment report."""
from html import escape
import json

from .evidence import sanitize
from .finding_views import finding_views, findings_summary, confidence_note, priority_note, RISK_ORDER


def risk_class(value):
    level = str(value).lower()
    return 'risk-' + (level if level in RISK_ORDER else 'unknown')


def html_report(result):
    views = finding_views(result)
    summary = findings_summary(result)
    result = sanitize(result)
    e = lambda x: escape(str(x))
    counts = summary['severity']
    risk_tiles = ''.join(
        f'<div class="tile {risk_class(risk)}"><span>{e(risk.title())}</span><strong>{count}</strong></div>'
        for risk, count in counts.items())
    status = result.get('status', 'unknown')
    if status != 'completed':
        coverage_note = 'Assessment incomplete. Review the coverage and errors before drawing conclusions.'
    elif not views:
        coverage_note = 'No findings were recorded for the completed checks. This does not establish that the target is secure.'
    else:
        coverage_note = 'Review the findings in reported risk order. Confirm the evidence and context before applying fixes.'
    priority_rows = ''.join(
        f'<tr><td><a href="#finding-{v.index}">{e(v.finding["title"])}</a></td>'
        f'<td class="{risk_class(v.finding["severity"])}">{e(v.finding["severity"].title())}</td><td>{e(priority_note(v.finding)[0])}</td>'
        f'<td>{e(v.finding.get("confidence", "unknown"))}</td></tr>'
        for v in views)
    action_plan = ('<table><thead><tr><th>Finding</th><th>Reported risk</th><th>Suggested next step</th>'
                   '<th>Confidence</th></tr></thead><tbody>' + priority_rows + '</tbody></table>'
                   if views else '<p>No finding-specific actions recorded. Review assessment coverage.</p>')
    rows = ''.join(
        f'<article id="finding-{v.index}"><h3>{e(f["title"])}</h3>'
        f'<p class="severity {risk_class(f["severity"])}">{e(f["severity"].upper())} · {e(f["id"])} · Confidence: {e(f.get("confidence", "unknown"))} '
        f'· Source: {e(f.get("source", "legacy"))} · Identical observations: {v.occurrences}</p>'
        f'<p><b>{e(priority_note(f)[0])}:</b> {e(priority_note(f)[1])}</p>'
        f'<p>{e(confidence_note(f))}</p><h4>Observed evidence</h4><p>{e(f["evidence"])}</p>'
        f'<h4>Recommended remediation</h4><p>{e(f["remediation"])}</p>'
        '<p class="muted">After changes, retest the same authorized scope and profile. '
        'An absent finding alone does not prove resolution.</p></article>'
        for v in views for f in (v.finding,))
    coverage = e(json.dumps(result.get('coverage', {'profile': 'legacy v0.1'}), indent=2))
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel assessment</title>
<style>
body{{font:16px/1.6 system-ui,sans-serif;max-width:960px;margin:36px auto;padding:0 24px;color:#24252a;background:#f5f5f6}}
main{{background:white;padding:28px;border:1px solid #dedee1;border-radius:14px}}
h1,h2,h3,h4{{line-height:1.3}}h1{{margin:0}}h2{{margin-top:32px}}h4{{margin-bottom:4px}}
.eyebrow,.muted,small{{color:#555861}}.eyebrow{{font-size:13px;letter-spacing:2px;font-weight:700}}
.meta{{overflow-wrap:anywhere}}.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(105px,1fr));gap:8px}}
.tile{{border:1px solid #dedee1;border-radius:8px;padding:12px}}.tile span{{display:block;color:#555861;font-size:14px}}
.tile strong{{font-size:26px}}table{{width:100%;border-collapse:collapse;font-size:14px}}
th,td{{text-align:left;vertical-align:top;border-bottom:1px solid #dedee1;padding:10px;overflow-wrap:anywhere}}
a{{color:#303a54}}article{{border-top:1px solid #dedee1;padding:12px 0;overflow-wrap:anywhere}}
.severity{{font-size:13px;font-weight:bold}}
.risk-critical{{color:#ad1642}}.risk-high{{color:#a83b0e}}.risk-medium{{color:#805a00}}
.risk-low{{color:#176b43}}.risk-info{{color:#185b9e}}.risk-unknown{{color:#555861}}
.tile.risk-critical,.tile.risk-high,.tile.risk-medium,.tile.risk-low,.tile.risk-info,.tile.risk-unknown{{border-left:4px solid currentColor}}
.tile span{{color:inherit}}td[class^="risk-"]{{font-weight:600}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px;background:#f5f5f6;padding:12px}}
@media print{{body{{margin:0;padding:0;background:white}}main{{border:0;padding:0}}article{{break-inside:avoid}}a{{color:inherit}}}}
</style></head><body><main>
<div class="eyebrow">SENTINEL</div><h1>Security assessment</h1>
<p class="meta"><b>Target:</b> {e(result['target'])}<br><b>UTC:</b> {e(result['started'])}<br>
<b>Status:</b> {e(status)}<br><b>HTTP:</b> {e(result['http_status'])}<br><b>TLS negotiated:</b> {e(result['tls'])}<br>
<b>Profile:</b> {e(result.get('profile','web-v1'))}<br><b>Optional DNS domain:</b> {e(result.get('dns_domain') or 'Not requested')}</p>
<p>{e(result.get('error',''))}</p>
<h2>Results at a glance</h2><div class="tiles">{risk_tiles}</div>
<p><b>{summary['observations']} observations; {summary['distinct']} distinct findings; {summary['exact_repeats']} identical repeats.</b></p>
<p>{e(coverage_note)}</p>
<h2>What to review first</h2>
<p>Suggested priority follows the original reported severity, not a new risk score. Confidence describes evidence strength, not exploitability.</p>
{action_plan}
<h2>Finding details and fixes</h2>{rows}
<h2>Assessment coverage</h2><pre>{coverage}</pre>
<small>Scope and limitations depend on the selected profile. Findings are configuration or security indicators, not proof of exploitability. Evidence is redacted on a best-effort basis. Review reports before sharing. Retest after remediation.</small>
</main></body></html>'''

"""Lightweight command line for explicit, low-impact posture assessments."""
import argparse
import json
from pathlib import Path
from .engine import scan, Target
from .dnscheck import domain_name
from .report import html_report

def main(argv=None):
    p=argparse.ArgumentParser(description='Sentinel: one authorized URL configuration assessment; optional exact-domain DNS posture.')
    p.add_argument('url'); p.add_argument('--authorized',action='store_true',help='Attest explicit permission for URL and optional DNS domain')
    p.add_argument('--dns-domain',default='');p.add_argument('--json-out',type=Path);p.add_argument('--html-out',type=Path)
    a=p.parse_args(argv)
    if not a.authorized:p.error('Explicit --authorized is required.')
    try:
        Target.parse(a.url)
        if a.dns_domain:domain_name(a.dns_domain)
        r=scan(a.url,True,dns_domain=a.dns_domain).to_dict()
        payload=json.dumps(r,indent=2,ensure_ascii=False)
        if a.json_out:a.json_out.write_text(payload,encoding='utf-8')
        if a.html_out:a.html_out.write_text(html_report(r),encoding='utf-8')
        print(payload)
        return 0 if r['status']=='completed' else 2
    except (ValueError,OSError) as e:p.error(str(e))

if __name__=='__main__':raise SystemExit(main())

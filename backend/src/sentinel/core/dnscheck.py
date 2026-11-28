"""Opt-in DNS posture assessment for one explicitly approved mail domain.
Uses the system-configured resolver via optional dnspython; no enumeration.
"""
import re
import ipaddress

def domain_name(value):
    value=value.strip().rstrip('.').lower()
    try: value=value.encode('idna').decode('ascii')
    except UnicodeError as e: raise ValueError('Invalid domain') from e
    if len(value)>253 or '.' not in value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in value.split('.')):
        raise ValueError('Enter an exact DNS domain, not a URL or IP address.')
    try: ipaddress.ip_address(value)
    except ValueError: return value
    raise ValueError('Enter a DNS domain, not an IP address.')

def analyze(records):
    from .engine import Finding
    out=[]
    def add(i,s,t,e,r):out.append(Finding(i,s,t,e,r))
    if records.get('spf',{}).get('status')=='ok':
        vals=[x for x in records['spf']['values'] if re.match(r'^v=spf1(?:\s|$)',x,re.I)]
        if not vals: add('DNS_SPF_MISSING','info','SPF record not observed','No SPF record in the domain TXT answer.','If the domain sends mail, publish an SPF policy covering authorized senders; if it never sends mail, consider an explicit deny policy.')
        elif len(vals)>1: add('DNS_SPF_MULTIPLE','medium','Multiple SPF records','More than one SPF record was observed; evaluation may fail.','Consolidate into a single valid SPF policy.')
        elif re.search(r'(?:^|\s)\+?all(?:\s|$)',vals[0],re.I): add('DNS_SPF_ALLOW_ALL','medium','SPF permits all senders','An unqualified or +all mechanism was observed.','Inventory legitimate sending services and use a restrictive policy after testing.')
    if records.get('dmarc',{}).get('status')=='ok':
        vals=[x for x in records['dmarc']['values'] if re.match(r'^v\s*=\s*DMARC1\s*(?:;|$)',x,re.I)]
        if not vals: add('DNS_DMARC_MISSING','info','Exact-domain DMARC record not observed','No DMARC record was found at the exact approved domain; inherited policy was not evaluated.','Review organizational-domain policy and publish appropriate DMARC with reporting.')
        elif len(vals)>1: add('DNS_DMARC_MULTIPLE','medium','Multiple DMARC records','Multiple DMARC policy records were observed.','Publish a single valid DMARC policy.')
        elif re.search(r'(?:^|;)\s*p\s*=\s*none\s*(?:;|$)',vals[0],re.I): add('DNS_DMARC_MONITOR','info','DMARC monitoring policy observed','The exact-domain policy is p=none; alignment and inherited policy were not tested.','Review aggregate reports, align legitimate senders, then consider quarantine or reject.')
    return out

def query_domain(value, authorized=False, cancel=None, resolver=None):
    if authorized is not True: raise PermissionError('Explicit DNS authorization required.')
    name=domain_name(value)
    if resolver is None:
        try:
            import dns.resolver
        except ImportError: return {'status':'unavailable','checks':{},'findings':[], 'error':'Optional dnspython package not installed.'}
        try: resolver=dns.resolver.Resolver()
        except Exception: return {'status':'unavailable','checks':{},'findings':[], 'error':'System DNS resolver could not be initialized.'}
    records={}
    for key,host,kind in [('spf',name,'TXT'),('dmarc','_dmarc.'+name,'TXT'),('mx',name,'MX'),('caa',name,'CAA')]:
        if cancel and cancel.is_set(): break
        try:
            answer=resolver.resolve(host+'.',kind,lifetime=3,search=False)
            vals=[''.join(x.decode('utf-8',errors='replace') for x in r.strings) for r in answer] if kind=='TXT' else []
            records[key]={'status':'ok','values':vals,'count':len(answer)}
        except Exception as e:
            missing=type(e).__name__ in ('NXDOMAIN','NoAnswer')
            records[key]={'status':'ok' if missing else 'unknown','values':[],'count':0 if missing else None}
    findings=analyze(records)
    return {'status':'completed' if len(records)==4 and all(x['status']=='ok' for x in records.values()) else 'partial','checks':{k:{'status':v['status'],'count':v['count']} for k,v in records.items()},'findings':findings,'error':''}

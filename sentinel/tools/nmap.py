"""Nmap: find which network services a system you own is exposing.

Three fixed profiles, no user-supplied scripts, no OS detection, no exploitation. Results
become plain-English findings; an open port is an exposure indicator, not a
confirmed vulnerability.
"""
from xml.etree import ElementTree as ET

from ..engine import Finding
from . import runner
from .base import Profile, ToolMissing, ToolSpec, find_binary as _find, execute

INSTALL_HINT = ('Nmap is not installed. On Kali/Debian/Ubuntu run: sudo apt install nmap\n'
                'On Windows or macOS download it from https://nmap.org/download and restart Sentinel.')

PROFILES = {
    'quick': Profile('quick', 'Quick check', 'The 100 most common ports. Usually under a minute.',
                     ('-F', '--open', '--host-timeout', '5m'), 600, 'top 100 TCP ports, no version detection'),
    'standard': Profile('standard', 'Standard', 'The 1,000 most common ports, and identifies what software is listening.',
                        ('--top-ports', '1000', '--open', '-sV', '--version-light', '--host-timeout', '15m'), 1800,
                        'top 1000 TCP ports, light version detection'),
    'all-ports': Profile('all-ports', 'All ports (slow)', 'Every one of the 65,535 TCP ports. Can take a long time.',
                         ('-p-', '--open', '-sV', '--version-light', '--host-timeout', '60m'), 4200,
                         'all 65535 TCP ports, light version detection'),
}

# port -> (label, severity on private network, severity if internet-reachable, why it matters, what to do)
RISKY = {
    21: ('FTP', 'medium', 'high', 'FTP sends usernames, passwords and files without encryption.',
         'Replace FTP with SFTP or FTPS, or turn the service off if it is not needed.'),
    23: ('Telnet', 'high', 'high', 'Telnet is unencrypted and a classic target for password guessing.',
         'Turn Telnet off and use SSH instead.'),
    111: ('RPC portmapper', 'low', 'medium', 'Lists services that can be reached remotely and is rarely needed.',
          'Disable rpcbind unless you use NFS, and block the port with a firewall.'),
    135: ('Windows RPC', 'low', 'high', 'Windows management service that should not be reachable from untrusted networks.',
          'Block this port at the firewall except from trusted admin machines.'),
    139: ('NetBIOS file sharing', 'low', 'high', 'Legacy Windows file sharing.', 'Disable NetBIOS over TCP/IP and block the port.'),
    445: ('SMB file sharing', 'medium', 'high', 'Windows/Samba file sharing has a long history of serious vulnerabilities.',
          'Block it from untrusted networks, disable SMBv1 and keep the system updated.'),
    2049: ('NFS', 'medium', 'high', 'Network file system; misconfigured exports can expose files.',
           'Restrict exports to specific hosts and block the port from untrusted networks.'),
    3306: ('MySQL/MariaDB', 'medium', 'high', 'A database should not accept connections from every machine.',
           'Bind it to localhost or a private interface and firewall it.'),
    3389: ('Remote Desktop (RDP)', 'medium', 'high', 'Exposed remote desktop is a common ransomware entry point.',
           'Put RDP behind a VPN, require Network Level Authentication and strong passwords or MFA.'),
    5432: ('PostgreSQL', 'medium', 'high', 'A database should not accept connections from every machine.',
           'Limit listen_addresses and pg_hba.conf to the machines that need it and firewall the port.'),
    5900: ('VNC remote screen', 'medium', 'high', 'VNC often has weak or no authentication and weak encryption.',
           'Tunnel it through SSH or a VPN, or turn it off.'),
    6379: ('Redis', 'high', 'high', 'Redis has no password by default and can often be taken over when exposed.',
           'Bind to localhost, set a strong password and firewall the port.'),
    9200: ('Elasticsearch', 'medium', 'high', 'Exposed Elasticsearch has repeatedly leaked whole databases.',
           'Enable authentication and bind it to a private interface.'),
    11211: ('Memcached', 'medium', 'high', 'Memcached has no authentication and is abused for data theft and attacks.',
            'Bind to localhost and firewall the port.'),
    1433: ('Microsoft SQL Server', 'medium', 'high', 'A database should not accept connections from every machine.',
           'Restrict access to application servers and firewall the port.'),
    27017: ('MongoDB', 'medium', 'high', 'Exposed MongoDB instances without authentication are frequently emptied by attackers.',
            'Enable authentication and bind it to a private interface.'),
}


def find_binary():
    return _find(SPEC)


def build_argv(binary, target, profile):
    argv = [binary, '-sT', '-n', '-T3', '--max-retries', '2', '-oX', '-']
    if ':' in target.value:
        argv.append('-6')
    if target.hosts == 1:
        argv.append('-Pn')   # one host: skip ping so firewalled hosts are not reported as "down"
    argv.extend(PROFILES[profile].args)
    argv.extend(['--', target.value])
    return argv


def parse_xml(xml_text):
    """Return a list of hosts: {'addr', 'name', 'ports': [{'proto','port','service','detail'}]}."""
    if '<!entity' in xml_text.lower():
        raise ValueError('Unexpected XML entity declaration in tool output.')
    root = ET.fromstring(xml_text)
    hosts = []
    for h in root.findall('host'):
        st = h.find('status')
        if st is None or st.get('state') != 'up':
            continue
        addr = next((a.get('addr') for a in h.findall('address') if a.get('addrtype') in ('ipv4', 'ipv6')), None)
        if not addr:
            continue
        hn = h.find('hostnames/hostname')
        ports = []
        for p in h.findall('ports/port'):
            state = p.find('state')
            if state is None or state.get('state') != 'open':
                continue
            svc = p.find('service')
            parts = [svc.get(k) for k in ('product', 'version', 'extrainfo')] if svc is not None else []
            ports.append({'proto': p.get('protocol', 'tcp'), 'port': int(p.get('portid')),
                          'service': runner.clean(svc.get('name') if svc is not None else '', 40) or 'unknown',
                          'detail': runner.clean(' '.join(x for x in parts if x), 100)})
        hosts.append({'addr': runner.clean(addr, 64), 'name': runner.clean(hn.get('name') if hn is not None else '', 80),
                      'ports': ports})
    return hosts


def findings_from_hosts(hosts, private):
    out = []
    for h in hosts:
        for p in h['ports']:
            fid = f"NMAP_{h['addr']}_{p['proto']}_{p['port']}"
            what = f"{p['service']}" + (f" ({p['detail']})" if p['detail'] else '')
            evidence = f"{h['addr']} accepts connections on {p['proto']}/{p['port']}: {what}."
            risk = RISKY.get(p['port']) if p['proto'] == 'tcp' else None
            if risk:
                label, sev_private, sev_public, why, fix = risk
                out.append(Finding(fid, sev_private if private else sev_public, f"{label} reachable on {h['addr']}",
                                   evidence + ' Port-based risk estimate; the associated service and its configuration are not confirmed. ' + why, fix))
            else:
                out.append(Finding(fid, 'info', f"Open port {p['port']}/{p['proto']} on {h['addr']}", evidence,
                                   'If nothing needs this service, stop it or block the port with a firewall. '
                                   'Every reachable service is something that must be kept updated.'))
    order = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
    return sorted(out, key=lambda f: (order.get(f.severity, 9), f.id))


def _parse(text, private):
    hosts = parse_xml(text)
    note = '' if hosts else 'No responding hosts found. That does not prove the target is offline or safe.'
    return findings_from_hosts(hosts, private), {'hosts_up': len(hosts)}, note


SPEC = ToolSpec('nmap', 'Nmap port scan', 'Finds the network services (open ports) a system is exposing.', 'net',
                ('nmap',), INSTALL_HINT, PROFILES, lambda b, t, p, o: build_argv(b, t, p), _parse,
                win_paths=('Nmap\\nmap.exe',),
                extra_coverage={'udp': 'not scanned', 'scripts': 'no user-selected NSE; version detection may invoke version-category scripts', 'os_detection': 'not performed'})


def scan_network(value, profile='quick', attested=False, typed_confirmation='', cancel=None, **kw):
    return execute(SPEC, value, profile, attested, typed_confirmation, cancel, **kw)

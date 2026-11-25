"""Summarize existing tool exports without launching tools or retaining files."""
from collections import Counter
import csv
import io
import json
import xml.etree.ElementTree as ET

MAX_REPORT = 5 * 1024 * 1024


def zap(text):
    report = json.loads(text)
    if not isinstance(report, dict) or not isinstance(report.get('site'), list):
        raise ValueError('Choose a ZAP Traditional JSON report.')
    sites = report['site']
    risks = Counter()
    for site in sites:
        if not isinstance(site, dict) or not isinstance(site.get('alerts'), list):
            raise ValueError('Expected an alerts list for each ZAP site.')
        for alert in site['alerts']:
            if not isinstance(alert, dict):
                raise ValueError('Expected ZAP alert objects.')
            risk = str(alert.get('riskcode', ''))
            risks[{'0': 'Informational', '1': 'Low', '2': 'Medium', '3': 'High'}.get(risk, 'Unknown')] += 1
    return {'Sites in report': len(sites), 'Alert types reported': risks.total(), **risks}


def nmap(text):
    text = text.replace('<!DOCTYPE nmaprun>', '', 1)
    if '<!DOCTYPE' in text or '<!ENTITY' in text:
        raise ValueError('Unsupported XML declarations in Nmap report.')
    root = ET.fromstring(text)
    if root.tag != 'nmaprun' or root.get('scanner') != 'nmap':
        raise ValueError('Choose an Nmap XML report.')
    states = Counter()
    for port in root.iterfind('host/ports/port'):
        state = port.find('state')
        states['Explicitly listed ports'] += 1
        if state is not None and state.get('state') == 'open':
            states['Explicitly open ports'] += 1
    return {
        'Hosts in report': len(root.findall('host')),
        'Explicitly listed ports': states['Explicitly listed ports'],
        'Explicitly open ports': states['Explicitly open ports'],
    }


def wireshark(text):
    rows = csv.reader(io.StringIO(text, newline=''), strict=True)
    columns = [column.strip().casefold() for column in next(rows, [])]
    if 'protocol' not in columns:
        raise ValueError('Choose a Wireshark packet-list CSV with a Protocol column.')
    protocol = columns.index('protocol')
    counts = Counter()
    for row in rows:
        if not row:
            continue
        if len(row) != len(columns):
            raise ValueError('A packet row does not match the CSV column headings.')
        counts[row[protocol].strip()[:60] or 'Unknown'] += 1
    return {'Packets in export': counts.total(), 'Top protocols': dict(counts.most_common(12))}


def summarize(tool, raw):
    parser = {'zap': zap, 'nmap': nmap, 'wireshark': wireshark}.get(tool)
    if parser is None:
        raise ValueError('Choose a supported report format.')
    try:
        return parser(raw.decode('utf-8-sig'))
    except (UnicodeError, json.JSONDecodeError, csv.Error, ET.ParseError, RecursionError) as exc:
        raise ValueError('This file could not be read as the selected UTF-8 report format.') from exc

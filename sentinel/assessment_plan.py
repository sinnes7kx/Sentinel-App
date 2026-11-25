"""Offline, advisory website assessment plans; never resolves or contacts a target."""
from dataclasses import dataclass
from ipaddress import ip_address

from .engine import Target
from .tools import sslscan, whatweb


@dataclass(frozen=True)
class PlanStep:
    title: str
    engine: str
    coverage: str
    note: str


@dataclass(frozen=True)
class AssessmentPlan:
    target: str
    profile: str
    steps: tuple
    limitations: tuple


def website_plan(value, profile, rows):
    if profile not in ('Quick', 'Standard', 'Extended'):
        raise ValueError('Choose Quick, Standard or Extended.')
    target = Target.parse(value)
    try:
        ip = ip_address(target.host)
    except ValueError:
        ip = None
    local = (target.host.rstrip('.').lower() == 'localhost' or
             (ip is not None and (ip.is_loopback or ip.is_unspecified or ip.is_link_local)))
    states = {row.name: row.state for row in rows}
    steps = [PlanStep('Website configuration', 'Built-in Python',
                      'Single exact URL: HTTPS, headers and cookies.',
                      'Existing quick assessment; explicit permission required.')]

    def recommend(spec, title, coverage):
        if states.get(spec.name) == 'Detected':
            return PlanStep(title, 'Native candidate', coverage,
                            'Executable detected; version and scan compatibility unverified.')
        if not local:
            for backend in ('Docker', 'WSL'):
                if states.get(backend + ' / ' + spec.id) == 'Version reported':
                    return PlanStep(title, backend + ' candidate', coverage,
                                    'Prepared tool reported a version; connectivity and scan compatibility unverified.')
        return PlanStep(title, 'Not available / verified', coverage,
                        'Check engines or prepare tools. Local addresses require a native candidate.')

    if profile in ('Standard', 'Extended'):
        if target.scheme == 'https':
            steps.append(recommend(sslscan.SPEC, 'TLS protocol and cipher review',
                                   'Optional manual sslscan review; not part of automated Standard.'))
        else:
            steps.append(PlanStep('TLS protocol and cipher review', 'Not applicable',
                                  'HTTPS required.', 'No automatic upgrade or alternate target.'))
        if ip is None:
            steps.append(PlanStep('Technology identification', 'Deferred',
                                  'WhatWeb identifies software; not a vulnerability test.',
                                  'Hostname-based external checks lack strict IP egress enforcement.'))
        else:
            steps.append(recommend(whatweb.SPEC, 'Technology identification',
                                   'Optional manual passive identification on the exact authorized IP URL.'))

        steps.append(PlanStep('Modern TLS verification', 'Built-in Python',
                              'TLS 1.2 and 1.3; same connected address and port, certificate verification retained.'
                              if target.scheme == 'https' else 'Not applicable to HTTP.',
                              'Failed negotiation is inconclusive; no legacy protocol or cipher enumeration.'))
    if profile == 'Extended':
        steps.append(PlanStep('Cross-origin policy verification', 'Built-in Python',
                              'Up to two anonymous GET requests to the same URL and connected address.',
                              'Checks origin reflection; no credentials or sensitive data access is tested.'))
    return AssessmentPlan(target.url, profile, tuple(steps), (
        'Recommendations are advisory, not authorization or execution readiness.',
        'Quick, Standard and Extended are available; external candidate checks are manual only.',
        'No DNS lookup, redirect following, discovery or target contact during planning.',
        'Site-wide crawling, injection, authenticated testing and exploit validation are not covered.',
        'External tools require separate review and authorization in Security tools.',
    ))

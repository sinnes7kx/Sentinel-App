"""Conservative OSV ECOSYSTEM range evaluation for PyPI (PEP 440).

See https://ossf.github.io/osv-schema/#evaluation and packaging.version.
Unsupported/invalid semantics return None, never an unaffected result.
"""
try:
    from packaging.version import Version, InvalidVersion
except ImportError:
    Version = None
    InvalidVersion = ValueError


def require_packaging():
    if Version is None:
        raise RuntimeError('Dependency assessment requires packaging. Run: python -m pip install -r requirements-intelligence.txt')


def parsed_version(value):
    require_packaging()
    parsed = Version(value)
    if parsed.local is not None:
        raise InvalidVersion('Local builds require separate provenance assessment.')
    return parsed


def match_range(candidate, specification):
    """Return (True/False/None, reason); validate all boundaries before matching."""
    if specification.get('type') != 'ECOSYSTEM':
        return None, 'unsupported_range_type'
    events = specification.get('events', [])
    timeline, limits = [], []
    try:
        for event in events:
            kind, raw = next(iter(event.items()))
            if kind == 'limit':
                limits.append(None if raw == '*' else parsed_version(raw))
            else:
                # introduced="0" is a sentinel before every version, including 0.dev0.
                boundary = None if kind == 'introduced' and raw == '0' else parsed_version(raw)
                timeline.append((boundary, kind))
    except (InvalidVersion, TypeError):
        return None, 'invalid_or_local_boundary'
    if not any(kind == 'introduced' for _, kind in timeline):
        return None, 'missing_introduced_event'
    if {'fixed', 'last_affected'} <= {kind for _, kind in timeline}:
        return None, 'mixed_fixed_and_last_affected'
    timeline.sort(key=lambda item: (item[0] is not None, item[0]))
    # Equal normalized boundaries with different event types have ambiguous ordering.
    for previous, current in zip(timeline, timeline[1:]):
        if previous[0] == current[0] and previous[1] != current[1]:
            return None, 'conflicting_equal_boundaries'
    if limits and not any(limit is None or candidate < limit for limit in limits):
        return False, 'outside_range_limits'
    vulnerable = False
    for boundary, kind in timeline:
        if kind == 'introduced' and (boundary is None or candidate >= boundary):
            vulnerable = True
        elif kind == 'fixed' and candidate >= boundary:
            vulnerable = False
        elif kind == 'last_affected' and candidate > boundary:
            vulnerable = False
    return vulnerable, 'ecosystem_range'


def match_affected(version, affected):
    """Union of explicit versions and ranges, with unknowns preserved on non-match."""
    try:
        candidate = parsed_version(version)
    except InvalidVersion:
        return None, ['invalid_or_local_inventory_version']
    unknown, evidence = set(), []
    versions = affected.get('versions', [])
    for raw in versions:
        try:
            if candidate == parsed_version(raw):
                evidence.append('explicit_version')
        except InvalidVersion:
            unknown.add('invalid_or_local_advisory_version')
    ranges = affected.get('ranges', [])
    for specification in ranges:
        matched, reason = match_range(candidate, specification)
        if matched is True:
            evidence.append(reason)
        elif matched is None:
            unknown.add(reason)
    if evidence:
        return True, sorted(set(evidence))
    if not versions and not ranges:
        unknown.add('missing_version_information')
    return (None, sorted(unknown)) if unknown else (False, ['outside_supplied_affected_versions'])

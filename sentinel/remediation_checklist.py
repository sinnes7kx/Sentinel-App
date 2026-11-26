"""Read-only checklist projection over saved findings and manual review states."""
from dataclasses import dataclass
from .finding_views import finding_views
from .store import REMEDIATION_STATES

FILTERS = ('All', *REMEDIATION_STATES)


@dataclass(frozen=True)
class ChecklistRow:
    index: int
    title: str
    severity: str
    state: str
    occurrences: int


def checklist(result, reviews):
    rows = []
    for view in finding_views(result or {}):
        state = reviews.get(view.index, {}).get('state', 'Open')
        if state not in REMEDIATION_STATES:
            state = 'Open'
        rows.append(ChecklistRow(view.index, view.finding['title'],
                                 view.finding['severity'], state, view.occurrences))
    return rows


def counts(rows):
    totals = dict.fromkeys(REMEDIATION_STATES, 0)
    for row in rows:
        totals[row.state] += 1
    return totals


def filtered(rows, state):
    if state not in FILTERS:
        raise ValueError('Unknown checklist filter.')
    return [row for row in rows if state == 'All' or row.state == state]

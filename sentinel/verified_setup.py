"""Combine explicit toolkit preparation with bounded offline verification."""
from .tool_setup import setup
from .tool_selfcheck import check_installation
from .tools.backends import Backend


def prepare_verified(kind, cancel, prepare=setup, verify=check_installation):
    outcome = prepare(kind, cancel)
    if (kind not in ('all', 'toolkit') or outcome.get('status') != 'completed'
            or outcome.get('backend') != 'docker'):
        return outcome
    if cancel.is_set():
        return dict(outcome, status='cancelled',
                    message='Toolkit prepared; verification cancelled. Installed components retained.')
    backend = Backend('docker', outcome['environment'])
    backend.validate('sslscan')
    checked = verify(cancel, preference=lambda: backend)
    status = checked['status']
    if status != 'completed':
        return dict(outcome, status=status, verification=checked,
                    message='Toolkit prepared, but offline verification is incomplete. ' + checked['message'],
                    next_action='retry' if status != 'cancelled' else 'cancelled')
    return dict(outcome, verification=checked,
                message='Toolkit prepared and offline version checks passed. Scan connectivity is not verified.')

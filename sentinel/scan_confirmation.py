"""One-time desktop scan confirmation; no network resolution in the dialog."""
import ipaddress
from tkinter import messagebox, simpledialog

from .engine import Target
from .tools.scope import parse_net_target


def confirm_website(parent, target, profile, dns):
    detail = 'Target: ' + target + '\nAssessment: ' + profile
    if dns:
        detail += '\nDNS domain: ' + dns
    return messagebox.askokcancel('Confirm assessment', detail +
        '\n\nStart this assessment? By continuing, you confirm authorization for the displayed scope.',
        parent=parent, default=messagebox.CANCEL)


def confirm_tool(parent, tool, value, profile, backend):
    """Return typed confirmation or None on cancellation. Preserve public-scope guard."""
    if tool.kind == 'web':
        target = Target.parse(value)
        if tool.schemes and target.scheme not in tool.schemes:
            raise ValueError('This check requires ' + ' or '.join(tool.schemes) + '.')
        subject = target.host
        display = target.url
    else:
        subject = display = value.strip()
    # Numeric private scopes can use a simple confirmation. Hostnames are
    # conservatively treated as potentially public without performing DNS.
    try:
        address = ipaddress.ip_network(subject, strict=True) if '/' in subject else ipaddress.ip_address(subject)
    except ValueError:
        private = False
    else:
        scope = parse_net_target(subject)
        subject = scope.value
        private = scope.private
    detail = ('Target: ' + display + '\nCheck: ' + tool.name +
              '\nProfile: ' + tool.profiles[profile].label + '\nEngine: ' + backend.kind)
    if backend.environment:
        detail += '\nEnvironment: ' + backend.environment
    if backend.kind == 'wsl':
        detail += '\n\nWSL cancellation is limited: Linux work may continue until its profile time limit.'
    if backend.kind == 'docker':
        detail += '\n\nDocker network access is not limited to the target.'
    detail += '\n\nContinuing confirms authorization for this exact scope.'
    if private:
        return '' if messagebox.askokcancel('Confirm assessment', detail + '\n\nStart assessment?',
                                           parent=parent, default=messagebox.CANCEL) else None
    typed = simpledialog.askstring('Confirm assessment', detail +
        '\n\nType the hostname or IP to confirm: ' + subject, parent=parent)
    if typed is None:
        return None
    if typed.strip().lower() != subject.lower():
        raise PermissionError('Confirmation did not match the displayed target. No assessment started.')
    return typed.strip()

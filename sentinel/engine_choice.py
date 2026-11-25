"""Choose an existing engine candidate without resolving or contacting a target.

Never install, launch or change an authorized assessment automatically.
"""
from dataclasses import dataclass
from ipaddress import ip_address
import re

from .engine import Target
from .tools.backends import Backend


@dataclass(frozen=True)
class Recommendation:
    backend: Backend | None
    explanation: str


def recommend(tool, value, native_detected, saved=None, docker_detected=False):
    if tool.id == 'web-checkup':
        return Recommendation(Backend(), 'Use the website checkup. Native tools and the saved managed toolkit are selected when compatible; missing checks are reported.')
    if native_detected:
        return Recommendation(Backend(), 'Use the tool already installed on this computer. No separate Linux setup needed.')
    if tool.id not in ('whatweb', 'sslscan'):
        return Recommendation(None, 'This tool is not detected. Open Tool setup to prepare supported tools.')
    try:
        target = Target.parse(value)
    except ValueError:
        return Recommendation(None, 'Enter the complete website address first.')
    if tool.schemes and target.scheme not in tool.schemes:
        return Recommendation(None, 'This check requires an HTTPS address.')
    try:
        address = ip_address(target.host)
    except ValueError:
        return Recommendation(None, 'For automatic container selection, use an authorized IP address URL. For website names, use a native tool or review advanced settings.')
    if (address.is_loopback or address.is_link_local or address.is_unspecified
            or address.is_multicast or address.is_reserved or getattr(address, 'scope_id', None)
            or getattr(address, 'ipv4_mapped', None) is not None):
        return Recommendation(None, 'This address is not suitable for automatic container selection. Use a native tool for local services.')
    if saved and saved.kind == 'docker' and re.fullmatch(r'sha256:[0-9a-f]{64}', saved.environment) and docker_detected:
        return Recommendation(saved, 'Use the saved managed toolkit. Docker and scan connectivity still need to work; container network access is not limited to the target.')
    return Recommendation(None, 'Prepare the managed toolkit in Tool setup, then choose the recommended setup again. WSL remains a manual option.')

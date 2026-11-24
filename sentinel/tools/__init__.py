"""Wrappers around external security tools (Kali Linux and others).

Rules every wrapper follows:
  * the tool is started with an argument list (never through a shell);
  * the target passes the scope guard in scope.py before anything runs;
  * only fixed, reviewed option sets ("profiles") are offered to users;
  * tool output is treated as untrusted data and sanitized before display;
  * results are returned as ordinary sentinel.engine.Scan objects, so history,
    comparison and reports work the same as for web assessments.
"""

from . import nmap, nikto, whatweb, sslscan   # noqa: E402
from .suite import SUITE                      # noqa: E402

# Order shown in the GUI. Anything with .id .name .blurb .kind .profiles .note .installed() .scan() fits.
TOOLS = [SUITE, nmap.SPEC, whatweb.SPEC, sslscan.SPEC, nikto.SPEC]

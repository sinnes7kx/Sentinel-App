# Local dependency checks

Use **Local dependencies** in Sentinel to select a pinned Python requirements
file or pip inspect JSON inventory and a local OSV advisory JSON array. Install
optional comparison support once with:

`python -m pip install -r requirements-intelligence.txt`

Assessment runs offline and never installs or imports the assessed packages.
The interface explains affected, unknown and no-match results and exports JSON.
Package names and results can be private: protect input files and exports.

The matcher supports PyPI PEP 440 versions and OSV ECOSYSTEM ranges, including
fixed boundaries and equivalent version spellings. Unsupported formats and local
builds stay unknown. Feed authenticity, freshness and completeness are not verified.
A non-match is not a security certificate. No automatic safe upgrade is inferred.

Try `examples/dependencies/requirements.txt` with
`examples/dependencies/advisories-synthetic.json`. These are fictional examples;
do not install the demonstration package. Expect one affected package.

The existing Nmap, SSLScan, Nikto and WhatWeb adapters are preserved. This change
adds the local dependency assessment feature from the other Sentinel development
branch; it does not replace or certify the network-tool adapters.

Run tests with `python -m unittest discover -s tests -v` after installing the
optional dependency. OpenSSL is required for the local TLS fixture.

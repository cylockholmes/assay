"""The redaction allowlist: public domains the Redactor must NOT pseudonymise.

This is NOT client data. It is the exception list for redaction's HOST
detector - generic, public domains (standards bodies, security references, and
RFC 2606 reserved placeholders) that carry no client information. When a
finding cites one of these, the AI should see the real reference rather than a
pseudonym like [HOST-07], so they are passed through unredacted.

The sensitive direction - the client's real hosts, which MUST be redacted - is
never here. Those are built at runtime from the engagement by
redact.terms_from_context() and never committed.

Kept in its own module so the allowlist can be read and tuned without wading
through the detector logic in redact.py.
"""

from __future__ import annotations

# Domains that belong to the security community, not to the client. These are
# the only hostnames allowed through, because they appear in our own reference
# links and carry no client information.
ALLOWED_DOMAINS = {
    "owasp.org", "cwe.mitre.org", "portswigger.net", "nvd.nist.gov",
    "cve.mitre.org", "example.com", "example.net", "example.org",
    "github.com", "projectdiscovery.io", "rfc-editor.org", "w3.org",
    "localhost", "ietf.org", "mitre.org", "first.org",
}

# Technology tokens that look like hostnames but are product names.
TECH_WORDS = {
    "spring.io", "asp.net", "vue.js", "node.js", "next.js", "nuxt.js",
    "jquery.js", "angular.js", "react.js", "d3.js", "bootstrap.css",
}

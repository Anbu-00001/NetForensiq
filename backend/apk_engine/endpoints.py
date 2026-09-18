"""
Network endpoints written into the code, each attributed to whoever wrote it.

The old module ran a domain regex over raw DEX bytes and reported 156 "domains"
for Flipkart. The first entries were ``%s``, ``%sadrevenue.%s``, ``%sapp.%s`` —
URL templates inside the AppsFlyer SDK (``com.appsflyer.internal``), which no
code contacts as written. That is the "it calls lots of DNS names" symptom.

A host is listed as the app's own only if it passes every check below.

1. **Shape.** From a ``scheme://host`` URL, an IP literal, or a bare string that
   is exactly a hostname. A host carrying a format placeholder is a template:
   counted, not listed.
2. **Real TLD**, per IANA's root-zone list (data/tlds.txt).
3. **A bare name must be used as one.** Strings like ``java.vm.name``,
   ``android.hardware.camera`` and ``com.android.chrome`` all end in real TLDs.
   A bare name is kept only if code referencing it also calls a networking API,
   or its registered domain also appears inside a real URL in the same package.
   Reverse-DNS identifiers (first label a TLD, e.g. ``com.``) and Java packages
   present in the DEX are rejected outright.
4. **Not an XML namespace.** ``http://schemas.android.com/apk/res/android`` is
   a URL by syntax and an identifier by convention; nothing fetches it.
5. **Attribution.** A host matching an Exodus tracker network signature, or
   referenced only from library code, is listed as SDK traffic. What remains is
   what the developer — or obfuscated code that may be the developer's — wrote,
   and only that feeds correlation with sealed captures.
"""

import ipaddress
import re
from urllib.parse import urlsplit

from . import reference

URL_RE = re.compile(r'\b(?:https?|wss?|ftp)://[^\s"\'<>`\\]{3,2048}', re.I)
HOST_RE = re.compile(r'^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$', re.I)
IPV4_RE = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
PLACEHOLDER_RE = re.compile(r'%[sdif0-9]|\{[^}]*\}|\$\{|<[^>]*>')

# Namespace identifiers that appear as URLs in manifests, layouts and XML
# parsers but are never network destinations.
XML_NAMESPACE_HOSTS = frozenset({
    'schemas.android.com', 'www.w3.org', 'w3.org', 'ns.adobe.com', 'xmlpull.org',
    'schemas.xmlsoap.org', 'schemas.microsoft.com', 'purl.org', 'xml.org',
})

MAX_LISTED = 300


def _ip_scope(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if (address.is_loopback or address.is_unspecified or address.is_multicast
            or address.is_link_local or address.is_reserved):
        return None
    return 'private' if address.is_private else 'global'


def _tracker_for(host):
    for pattern, name in reference.tracker_network_patterns():
        if pattern.search(host):
            return name
    return None


def _registered_domain(host):
    # Last two labels. Imprecise for multi-part suffixes (co.in), which only
    # makes the "seen in a URL" test stricter, never looser.
    return '.'.join(host.split('.')[-2:])


def _method_key(method):
    return (str(method.class_name), str(method.name), str(method.descriptor))


def extract(codemap):
    """Group every endpoint by host, split into the app's own and SDK traffic."""
    tlds = reference.tlds()
    packages = codemap.packages_in_code()
    network_methods = codemap.network_methods()
    hosts = {}           # host -> {'kind', 'examples', 'xrefs'}
    bare_candidates = []
    templates = 0

    def record(host, kind, example, xrefs):
        entry = hosts.setdefault(host, {'kind': kind, 'examples': [], 'xrefs': []})
        if example not in entry['examples'] and len(entry['examples']) < 3:
            entry['examples'].append(example)
        entry['xrefs'].extend(xrefs)

    for value, analysis in codemap.strings():
        if len(value) > 4096 or '.' not in value:
            continue

        urls = URL_RE.findall(value)
        for match in urls:
            url = match.rstrip('.,);]"\'')
            authority = url.split('/', 3)[2] if url.count('/') >= 2 else url
            if PLACEHOLDER_RE.search(authority):
                templates += 1
                continue
            try:
                host = (urlsplit(url).hostname or '').lower()
            except ValueError:
                continue
            if not host or host in XML_NAMESPACE_HOSTS:
                continue
            if IPV4_RE.match(host):
                if _ip_scope(host):
                    record(host, 'ip', url, list(analysis.get_xref_from()))
            elif HOST_RE.match(host) and host.rsplit('.', 1)[-1] in tlds:
                record(host, 'host', url, list(analysis.get_xref_from()))
        if urls:
            continue

        bare = value
        if IPV4_RE.match(bare):
            if _ip_scope(bare):
                bare_candidates.append((bare, 'ip', analysis))
        elif HOST_RE.match(bare) and bare == bare.lower():
            labels = bare.split('.')
            if (labels[-1] in tlds and labels[0] not in tlds
                    and bare not in packages and bare not in XML_NAMESPACE_HOSTS):
                bare_candidates.append((bare, 'host', analysis))

    url_domains = {_registered_domain(h) for h, e in hosts.items() if e['kind'] == 'host'}
    for bare, kind, analysis in bare_candidates:
        xrefs = list(analysis.get_xref_from())
        used_as_host = any(_method_key(m) in network_methods for _c, m in xrefs)
        if used_as_host or (kind == 'host' and _registered_domain(bare) in url_domains):
            record(bare, kind, bare, xrefs)

    app, sdk = [], []
    for host, entry in hosts.items():
        classes = sorted({str(c.name) for c, _m in entry['xrefs']})
        attributions = [codemap.attribute(c) for c in classes]
        tracker = _tracker_for(host)
        library_only = bool(attributions) and all(a['kind'] == 'library' for a in attributions)
        item = {
            'host': host, 'kind': entry['kind'], 'examples': entry['examples'],
            'referenced_by': classes[:5],
            'attribution': sorted({a['kind'] for a in attributions}) or ['unattributed'],
        }
        if tracker or library_only:
            item['sdk'] = tracker or next(a['name'] for a in attributions if a['kind'] == 'library')
            sdk.append(item)
        else:
            if entry['kind'] == 'ip':
                item['scope'] = _ip_scope(host)
            app.append(item)

    app.sort(key=lambda i: i['host'])
    sdk.sort(key=lambda i: (i['sdk'], i['host']))
    return {
        'app': app[:MAX_LISTED], 'sdk': sdk[:MAX_LISTED],
        'app_total': len(app), 'sdk_total': len(sdk),
        'templates_suppressed': templates,
    }


def hosts_for_correlation(endpoints):
    """Hosts and IPs the package's own code names — never SDK traffic."""
    names, ips = set(), set()
    for item in endpoints.get('app', []):
        (ips if item['kind'] == 'ip' else names).add(item['host'])
    return sorted(names), sorted(ips)

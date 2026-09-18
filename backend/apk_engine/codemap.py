"""
The package's code, indexed so a finding can say *who* does something.

The old module grepped DEX bytes for strings like ``/system/bin/su`` and scored
whatever it found. In Flipkart that string lives in four methods named
``isRooted`` — one of them NPCI's own UPI library — which check *whether* a
phone is rooted, an anti-fraud control. A string's presence says nothing about
who uses it or how. So every observation here is a call site or a string
reference with the calling class attached, and every calling class is
attributed:

* ``app``          — under the manifest package or a declared component's
                     package, so the developer wrote it;
* ``library``      — under a namespace owned by a known SDK (Exodus tracker
                     signatures, or the platform/toolchain namespaces below);
* ``unattributed`` — anything else. After R8/ProGuard, app code and library
                     code both end up in short names like ``La/b/c;``, so this
                     is the honest label for obfuscated code: it may be either.

Behaviour rules accept ``app`` and ``unattributed`` evidence and ignore
``library`` evidence — a library can *contain* a capability the app never uses.

Known limitation, stated in every report
========================================
androguard's call graph has no edges for Android lifecycle callbacks, listeners
or lambdas dispatched by the framework. A call path back to a manifest component
is shown when one is found; when none is found that is *not* evidence the code
is unreachable, and no rule is gated on it.
"""

import re
from collections import deque

# Namespaces owned by widely used platform, toolchain and SDK projects. Used
# only to *attribute* code, never to score it; tracker SDKs come from the
# Exodus signature database on top of this. Extend with the project name, not
# a guess.
WELL_KNOWN_NAMESPACES = {
    'java.': 'Java class library', 'javax.': 'Java extensions',
    'dalvik.': 'Android runtime', 'android.': 'Android framework',
    'androidx.': 'AndroidX (Google)', 'android.support.': 'Android Support Library (Google)',
    'kotlin.': 'Kotlin standard library (JetBrains)', 'kotlinx.': 'Kotlin extensions (JetBrains)',
    'org.jetbrains.': 'JetBrains annotations', 'org.intellij.': 'IntelliJ annotations',
    'com.google.android.gms.': 'Google Play services', 'com.google.firebase.': 'Firebase (Google)',
    'com.google.android.material.': 'Material Components (Google)',
    'com.google.android.play.': 'Google Play Core', 'com.google.common.': 'Guava (Google)',
    'com.google.gson.': 'Gson (Google)', 'com.google.protobuf.': 'Protocol Buffers (Google)',
    'com.google.crypto.tink.': 'Tink (Google)', 'com.google.android.datatransport.': 'Google DataTransport',
    'okhttp3.': 'OkHttp (Square)', 'okio.': 'Okio (Square)', 'retrofit2.': 'Retrofit (Square)',
    'com.squareup.': 'Square libraries', 'io.reactivex.': 'RxJava', 'dagger.': 'Dagger',
    'org.apache.': 'Apache libraries', 'org.json.': 'JSON-java', 'org.bouncycastle.': 'Bouncy Castle',
    'org.chromium.': 'Chromium', 'io.flutter.': 'Flutter engine', 'com.facebook.react.': 'React Native',
}

# Framework and common-library entry points that take a host or URL.
NETWORK_APIS = (
    ('Ljava/net/URL;', '<init>'), ('Ljava/net/URI;', '<init>'), ('Ljava/net/URI;', 'create'),
    ('Ljava/net/InetAddress;', 'getByName'), ('Ljava/net/InetAddress;', 'getAllByName'),
    ('Ljava/net/InetSocketAddress;', '<init>'), ('Ljava/net/Socket;', '<init>'),
    ('Ljavax/net/ssl/SSLSocketFactory;', 'createSocket'),
    ('Landroid/net/Uri;', 'parse'), ('Landroid/net/Uri$Builder;', 'authority'),
    ('Landroid/webkit/WebView;', 'loadUrl'),
    ('Lokhttp3/HttpUrl$Builder;', 'host'), ('Lokhttp3/HttpUrl;', 'parse'),
    ('Lokhttp3/HttpUrl$Companion;', 'parse'), ('Lokhttp3/Request$Builder;', 'url'),
)

MAX_DEX_BYTES = 512 * 1024 * 1024
PATH_MAX_DEPTH = 8
PATH_MAX_NODES = 4000


def dotted(descriptor):
    """``Lcom/foo/Bar;`` -> ``com.foo.Bar``."""
    name = str(descriptor)
    if name.startswith('L') and name.endswith(';'):
        name = name[1:-1]
    return name.replace('/', '.')


def descriptor(dotted_name):
    return 'L' + dotted_name.replace('.', '/') + ';'


class CodeMap:
    """Indexes the DEX files of an androguard ``APK``."""

    def __init__(self, apk, identity, tracker_signatures=()):
        from androguard.core.analysis.analysis import Analysis
        from androguard.core.dex import DEX

        self.identity = identity
        self.errors = []
        self.dex_count = 0
        self.dex_bytes = 0
        self.truncated = False
        self.dx = Analysis()

        for index, blob in enumerate(self._dex_blobs(apk)):
            if self.dex_bytes + len(blob) > MAX_DEX_BYTES:
                self.truncated = True
                self.errors.append(f'DEX #{index + 1} skipped: code budget of '
                                   f'{MAX_DEX_BYTES // (1024 * 1024)} MB reached.')
                continue
            try:
                self.dx.add(DEX(blob))
                self.dex_count += 1
                self.dex_bytes += len(blob)
            except Exception as exc:
                self.errors.append(f'DEX #{index + 1} could not be parsed: {exc}')
        if self.dex_count:
            self.dx.create_xref()

        self._libraries = sorted(
            [(prefix, name) for prefix, name in WELL_KNOWN_NAMESPACES.items()]
            + [(p, n) for p, n in tracker_signatures],
            key=lambda pair: -len(pair[0]))
        self._app_prefixes = self._app_namespaces()
        self._strings = None
        self._subclasses = None
        self._component_classes = self._components()

    def _dex_blobs(self, apk):
        try:
            yield from apk.get_all_dex()
        except Exception as exc:
            self.errors.append(f'DEX files could not be enumerated: {exc}')

    # ── attribution ────────────────────────────────────────────────────────

    def _resolve(self, name):
        package = self.identity.get('package') or ''
        if name.startswith('.'):
            return package + name
        if '.' not in name and package:
            return f'{package}.{name}'
        return name

    def library_of(self, dotted_name):
        for prefix, name in self._libraries:
            if dotted_name.startswith(prefix):
                return name
        return None

    def _app_namespaces(self):
        """
        Namespaces the developer owns.

        The manifest package, plus the packages of declared components and the
        application class — but only those under the same organisation prefix
        (the package's first two labels). The manifest merger copies SDK
        components into the app's manifest, so Flipkart declares activities in
        ``com.facebook``, ``in.juspay`` and ``org.npci.upi``; counting those as
        Flipkart's own code would put NPCI's root check back in the app column.
        """
        prefixes = set()
        package = self.identity.get('package') or ''
        if package:
            prefixes.add(package + '.')
        organisation = '.'.join(package.split('.')[:2]) + '.' if package.count('.') >= 1 else None
        names = [c['name'] for c in self.identity.get('components', []) if c.get('name')]
        if self.identity.get('application_class'):
            names.append(self.identity['application_class'])
        for name in names:
            full = self._resolve(name)
            if ('.' in full and not self.library_of(full)
                    and organisation and full.startswith(organisation)):
                prefixes.add(full.rsplit('.', 1)[0] + '.')
        return tuple(sorted(prefixes))

    def attribute(self, class_descriptor):
        name = dotted(class_descriptor)
        library = self.library_of(name)
        if library:
            return {'kind': 'library', 'name': library}
        if self._app_prefixes and name.startswith(self._app_prefixes):
            return {'kind': 'app', 'name': self.identity.get('package') or ''}
        return {'kind': 'unattributed', 'name': ''}

    def attribute_component(self, component_name):
        """
        Attribute a *manifest* component to the app or to a bundled library.

        The same question ``attribute`` answers for a class named in code, for a
        class named in the manifest — where the name may be relative (``.Foo``)
        and has to be resolved against the package first.
        """
        return self.attribute(descriptor(self._resolve(component_name)))

    def _components(self):
        classes = set()
        for c in self.identity.get('components', []):
            if c.get('name'):
                classes.add(descriptor(self._resolve(c['name'])))
        if self.identity.get('application_class'):
            classes.add(descriptor(self._resolve(self.identity['application_class'])))
        return classes

    # ── queries ────────────────────────────────────────────────────────────

    def subclasses_of(self, class_descriptor):
        """Every class in the package that extends ``class_descriptor``, transitively."""
        if self._subclasses is None:
            children = {}
            for cls in self.dx.get_classes():
                try:
                    parent = str(cls.extends)
                except Exception:
                    continue
                children.setdefault(parent, set()).add(str(cls.name))
            self._subclasses = children
        found, queue = set(), deque([class_descriptor])
        while queue:
            for child in self._subclasses.get(queue.popleft(), ()):
                if child not in found:
                    found.add(child)
                    queue.append(child)
        return found

    def calls(self, class_descriptor, method_name, include_subclasses=False):
        """
        Every call site of ``class_descriptor->method_name``.

        With ``include_subclasses``, calls made through an app subclass count
        too: a service extending AccessibilityService calls
        ``this.performGlobalAction()``, which the DEX records against the
        subclass, not against the framework class.
        """
        if not self.dex_count:
            return []
        owners = {class_descriptor}
        if include_subclasses:
            owners |= self.subclasses_of(class_descriptor)
        pattern = '^(' + '|'.join(re.escape(o) for o in sorted(owners)) + ')$'
        sites, seen = [], set()
        for method in self.dx.find_methods(classname=pattern,
                                           methodname='^' + re.escape(method_name) + '$'):
            for caller_class, caller_method, _offset in method.get_xref_from():
                key = (str(caller_class.name), str(caller_method.name),
                       str(caller_method.descriptor))
                if key in seen:
                    continue
                seen.add(key)
                sites.append(CallSite(self, caller_class, caller_method,
                                      f'{dotted(class_descriptor)}.{method_name}'))
        return sites

    def strings(self):
        if self._strings is None:
            self._strings = ([(str(s.get_value()), s) for s in self.dx.get_strings()]
                             if self.dex_count else [])
        return self._strings

    def string_sites(self, regex):
        """Strings matching ``regex`` (search semantics), with who references them."""
        pattern = re.compile(regex)
        results = []
        for value, analysis in self.strings():
            if not pattern.search(value):
                continue
            owners, seen = [], set()
            for caller_class, caller_method in analysis.get_xref_from():
                key = (str(caller_class.name), str(caller_method.name))
                if key not in seen:
                    seen.add(key)
                    owners.append(CallSite(self, caller_class, caller_method, None))
            results.append(StringSite(value, owners))
        return results

    def network_methods(self):
        """
        Methods that hand something to a networking API.

        Used to decide whether a bare string shaped like a hostname is being
        used as one: ``java.vm.name`` and ``android.hardware.camera`` have real
        TLDs as their last label and are not hosts.
        """
        if getattr(self, '_network_methods', None) is None:
            keys = set()
            for owner, method in NETWORK_APIS:
                for site in self.calls(owner, method):
                    m = site.caller_method
                    keys.add((str(m.class_name), str(m.name), str(m.descriptor)))
            self._network_methods = keys
        return self._network_methods

    def packages_in_code(self):
        """Every Java package that has a class in this DEX — to tell names from hosts."""
        packages = set()
        for cls in self.dx.get_classes() if self.dex_count else ():
            name = dotted(cls.name)
            while '.' in name:
                name = name.rsplit('.', 1)[0]
                packages.add(name)
        return packages

    def path_from_component(self, caller_method):
        """
        A chain of callers from a manifest component down to ``caller_method``.

        Breadth-first over "called by" edges, bounded in depth and nodes. None
        when nothing is found — which, because framework callbacks are not
        edges, does not mean unreachable.
        """
        start = caller_method
        queue = deque([(start, [start])])
        visited = {id(start)}
        while queue and len(visited) < PATH_MAX_NODES:
            method, chain = queue.popleft()
            owner = str(method.class_name)
            if owner in self._component_classes or owner.split('$')[0] + ';' in self._component_classes:
                return [method_label(m) for m in reversed(chain)]
            if len(chain) > PATH_MAX_DEPTH:
                continue
            for _cls, caller, _offset in method.get_xref_from():
                if id(caller) not in visited:
                    visited.add(id(caller))
                    queue.append((caller, chain + [caller]))
        return None


# Dalvik instructions that read their first register without writing it.
_READS_ONLY = ('if-', 'return', 'throw', 'monitor-', 'check-cast', 'fill-array-data',
               'packed-switch', 'sparse-switch', 'iput', 'sput', 'aput', 'goto', 'nop')


def method_label(method):
    return f'{dotted(method.class_name)}.{method.name}()'


class CallSite:
    """One method that calls an API, or references a string."""

    def __init__(self, codemap, caller_class, caller_method, callee):
        self.codemap = codemap
        self.caller_class = str(caller_class.name)
        self.caller_method = caller_method
        self.callee = callee
        self.attribution = codemap.attribute(self.caller_class)

    @property
    def counts_as_app_code(self):
        return self.attribution['kind'] in ('app', 'unattributed')

    def instructions(self):
        try:
            return list(self.caller_method.get_method().get_instructions())
        except Exception:
            return []

    def constant_arguments(self, method_name):
        """
        Constant values passed to each ``method_name`` invocation in this method.

        A linear scan that remembers the last constant loaded into each
        register — enough to see ``addRoute("0.0.0.0", 0)`` written plainly,
        and deliberately not a full data-flow analysis. Returns one list per
        invocation, None for any argument that is not a visible constant.
        """
        registers, invocations = {}, []
        for ins in self.instructions():
            name, output = ins.get_name(), ins.get_output()
            if name.startswith('const'):
                register, _, value = output.partition(', ')
                if name.startswith('const-string'):
                    value = value.strip()
                    if len(value) >= 2 and value[0] == value[-1] == '"':
                        value = value[1:-1]
                    registers[register] = value
                elif name == 'const-class':
                    registers[register] = value.strip()
                else:
                    try:
                        registers[register] = int(value.strip(), 0)
                    except ValueError:
                        registers[register] = None
            elif name.startswith('invoke') and f'->{method_name}(' in output:
                args = [a.strip() for a in output.split(', ') if a.strip().startswith('v')]
                values = [registers.get(a) for a in args]
                if 'static' not in name:
                    values = values[1:]          # drop the receiver
                invocations.append(values)
            elif not name.startswith(_READS_ONLY) and output.startswith('v'):
                # Any other instruction whose first operand is a register
                # writes to it; forget what was known rather than report a
                # stale constant as an argument.
                registers.pop(output.split(',')[0].strip(), None)
        return invocations

    def constant_values(self):
        """Every constant loaded anywhere in this method."""
        values = set()
        for ins in self.instructions():
            name, output = ins.get_name(), ins.get_output()
            if not name.startswith('const'):
                continue
            raw = output.partition(', ')[2].strip()
            if name.startswith('const-string'):
                values.add(raw.strip('"'))
            else:
                try:
                    values.add(int(raw, 0))
                except ValueError:
                    values.add(raw)
        return values

    def references(self, *values):
        """True if any const-string/const-class in this method equals one of ``values``."""
        wanted = set(values)
        for ins in self.instructions():
            if ins.get_name() in ('const-string', 'const-string/jumbo', 'const-class'):
                value = ins.get_output().partition(', ')[2].strip()
                if len(value) >= 2 and value[0] == value[-1] == '"':
                    value = value[1:-1]
                if value in wanted:
                    return True
        return False

    def evidence(self, with_path=True):
        item = {
            'caller': method_label(self.caller_method),
            'attribution': self.attribution,
        }
        if self.callee:
            item['calls'] = self.callee
        if with_path:
            item['path_from_component'] = self.codemap.path_from_component(self.caller_method)
        return item


class StringSite:
    def __init__(self, value, owners):
        self.value = value
        self.owners = owners

    @property
    def counts_as_app_code(self):
        # A string no code references cannot be attributed to a library, so it
        # is treated as the package's own.
        return not self.owners or any(o.counts_as_app_code for o in self.owners)

    def evidence(self, with_path=False):
        return {
            'value': self.value,
            'referenced_by': [o.evidence(with_path=with_path) for o in self.owners[:5]],
        }

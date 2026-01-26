# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple
from typing_extensions import Protocol, Hashable
from urllib.parse import ParseResult, urlparse, parse_qs, unquote, urlencode


# Internal URI scheme for secret references.
# We use the `scheme://authority/path` form; the authority component is the namespace (not a network host).
SECRET_SCHEME = 'secret'
SECRET_URI_SCHEME = f'{SECRET_SCHEME}://'


class CephSecretException(Exception):
    pass


class SecretScope(str, Enum):
    GLOBAL = 'global'
    SERVICE = 'service'
    HOST = 'host'

    @classmethod
    def from_str(cls, s: str) -> 'SecretScope':
        try:
            return SecretScope(s)
        except Exception as e:
            allowed = ', '.join(x.value for x in SecretScope)
            raise CephSecretException(
                f'Invalid secret scope {s!r}. Expected one of: {allowed}'
            ) from e


_SCOPE_VALUES = frozenset(s.value for s in SecretScope)


class SecretURI(Protocol, Hashable):
    def to_uri(self) -> str: ...


def _extract_key_param(parsed_url: ParseResult) -> Optional[str]:
    '''
    Extract key from query param (?key=...) or fragment (#...).

    Precedence: query parameter wins over fragment, e.g. '?key=a#b' -> 'a'.

    Policy:
      - Reject multiple 'key=' values
      - Reject empty key if explicitly provided
      - URL-decode fragment form
    '''
    q = parse_qs(parsed_url.query or '')
    vals = q.get('key')

    if vals is not None:
        if len(vals) != 1:
            raise ValueError(f'Invalid secret uri: multiple key parameters are not allowed: {vals!r}')
        key = vals[0].strip()
        if not key:
            raise ValueError('Invalid secret uri: key parameter must not be empty')
        return key

    if parsed_url.fragment:
        key = unquote(parsed_url.fragment).strip()  # Strip whitespace
        if not key:  # Now catches whitespace-only
            raise ValueError('Invalid secret uri: key fragment must not be empty')
        return key

    return None


def _validate_components_no_slash(
    *,
    uri: str,
    namespace: str,
    scope: SecretScope,
    target: str,
    name: str,
    key: Optional[str],
) -> None:
    if not namespace:
        raise ValueError(f'Invalid secret uri {uri!r}: namespace must not be empty')
    if not name:
        raise ValueError(f'Invalid secret uri {uri!r}: name must not be empty')
    if scope != SecretScope.GLOBAL and not target:
        raise ValueError(f'Invalid secret uri {uri!r}: target must not be empty')
    if key is not None and not key.strip():
        raise ValueError(f'Invalid secret uri {uri!r}: key must not be empty if specified')

    for label, val in (
        ('namespace', namespace),
        ('target', target),
        ('name', name),
        ('key', key or ''),
    ):
        if val and '/' in val:
            raise ValueError(f'Invalid secret uri {uri!r}: {label!r} must not contain \'/\'')


@dataclass(frozen=True)
class SecretRef:
    namespace: str
    scope: SecretScope
    target: str
    name: str
    key: Optional[str] = None

    def __post_init__(self) -> None:
        _validate_components_no_slash(
            uri='<SecretRef>',  # Clear marker it's from constructor
            namespace=self.namespace,
            scope=self.scope,
            target=self.target,
            name=self.name,
            key=self.key,
        )

    def ident(self) -> Tuple[str, str, str, str]:
        return (self.namespace, self.scope.value, self.target, self.name)

    def to_uri(self) -> str:
        # Components are already validated to not contain '/'
        if self.scope == SecretScope.GLOBAL:
            base = f'{SECRET_URI_SCHEME}{self.namespace}/{self.scope.value}/{self.name}'
        else:
            base = f'{SECRET_URI_SCHEME}{self.namespace}/{self.scope.value}/{self.target}/{self.name}'

        if self.key is not None:
            return f'{base}?{urlencode({"key": self.key})}'
        return base


@dataclass(frozen=True)
class BadSecretURI:
    raw: str
    error: str
    namespace: str

    def to_uri(self) -> str:
        return self.raw


def parse_secret_uri(uri: str, namespace: str) -> SecretRef:
    '''
    Parse a secret reference URI.

    Canonical form:
        secret://<namespace>/<scope>/<target>/<name>?key=<data_key>

    Global form:
        secret://<namespace>/global/<name>?key=<data_key>

    Backward/short form (namespace omitted):
        secret://<scope>/<target>/<name>?key=<data_key>

    Short global form:
        secret://global/<name>?key=<data_key>

    Fragment form is also accepted:
        secret://.../<name>#<data_key>

    Note: if both are present, query '?key=' takes precedence over fragment '#...'.
    '''
    if not isinstance(uri, str):
        raise ValueError('secret uri must be a string')

    parsed = urlparse(uri)
    if parsed.scheme != SECRET_SCHEME:
        raise ValueError(f'Not a secret uri: {uri!r}')

    # Decode percent-encoding for consistent internal representation
    netloc = unquote(parsed.netloc or '')
    path_str = (parsed.path or '').lstrip('/')

    # Tolerant: ignore empty segments (so '//' collapses). If you want strictness,
    # add a check like: if '//' in path_str: raise ValueError(...)
    parts = [unquote(p) for p in path_str.split('/') if p]

    key = _extract_key_param(parsed)

    if netloc in _SCOPE_VALUES:
        # Short form: secret://<scope>/<...>
        scope = SecretScope.from_str(netloc)
        ns = namespace

        if scope == SecretScope.GLOBAL:
            if len(parts) < 1:
                raise ValueError(
                    f'Invalid secret uri {uri!r}. Expected {SECRET_URI_SCHEME}global/<name>[?key=...]'
                )
            target, name = '', parts[0]
        else:
            if len(parts) < 2:
                raise ValueError(
                    f'Invalid secret uri {uri!r}. Expected {SECRET_URI_SCHEME}<scope>/<target>/<name>[?key=...]'
                )
            target, name = parts[0], parts[1]
    else:
        # Canonical form: secret://<namespace>/<scope>/...
        if not netloc and not namespace:
            raise ValueError(f'Invalid secret uri {uri!r}: namespace not specified')

        ns = netloc or namespace

        if len(parts) < 2:
            raise ValueError(
                f'Invalid secret uri {uri!r}. Expected {SECRET_URI_SCHEME}<namespace>/<scope>/<target>/<name>[?key=...]'
            )

        scope = SecretScope.from_str(parts[0])

        if scope == SecretScope.GLOBAL:
            name = parts[1]
            target = ''
        else:
            if len(parts) < 3:
                raise ValueError(
                    f'Invalid secret uri {uri!r}. Expected {SECRET_URI_SCHEME}<namespace>/<scope>/<target>/<name>[?key=...]'
                )
            target, name = parts[1], parts[2]

    return SecretRef(namespace=ns, scope=scope, target=target, name=name, key=key)


def _coerce_scope(s: str) -> 'SecretScope':
    # Accept both enum values ('global') and enum names ('GLOBAL')
    if not isinstance(s, str):
        raise CephSecretException(f'Scope must be a string, got {type(s).__name__}')
    if not s.strip():
        raise CephSecretException('Scope must not be empty')

    s_norm = s.strip()
    try:
        return SecretScope(s_norm)
    except Exception:
        try:
            return SecretScope[s_norm.upper()]
        except Exception:
            allowed = ', '.join(x.value for x in SecretScope)
            raise CephSecretException(f'Unknown scope {s!r}. Expected one of: {allowed}')


def parse_secret_path(path: str) -> Tuple[str, 'SecretScope', str, str]:
    '''
    Parse a secret locator path:
      <namespace>/<scope>/<target>/<name>

    Also supports:
      <namespace>/global/<name>  -> target is empty
    '''
    p = (path or '').strip().strip('/')
    parts = [x for x in p.split('/') if x]

    if len(parts) == 4:
        ns, scope_s, target, name = parts
        scope = _coerce_scope(scope_s)
        if scope == SecretScope.GLOBAL and target:
            raise CephSecretException(
                f'Invalid secret path: global scope cannot have a target, got {target!r}'
            )
        return ns, scope, target, name

    if len(parts) == 3:
        ns, scope_s, name = parts
        scope = _coerce_scope(scope_s)
        if scope == SecretScope.GLOBAL:
            return ns, scope, '', name

    raise CephSecretException(
        'Invalid secret path. Use <namespace>/<scope>/<target>/<name> '
        'or <namespace>/global/<name>.'
    )

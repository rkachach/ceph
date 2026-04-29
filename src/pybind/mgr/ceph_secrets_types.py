# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Hashable, Protocol, Tuple
from urllib.parse import urlparse, unquote, quote


# Internal URI scheme for secret references.
# Canonical form has no authority: secret:/<namespace>/<scope>/...
SECRET_SCHEME = 'secret'


class CephSecretException(Exception):
    pass


class CephSecretDataError(CephSecretException):
    pass


class SecretScope(str, Enum):
    GLOBAL = 'global'
    SERVICE = 'service'
    HOST = 'host'
    CUSTOM = 'custom'

    @classmethod
    def from_str(cls, s: str) -> 'SecretScope':
        try:
            return SecretScope(s)
        except Exception as e:
            allowed = ', '.join(x.value for x in SecretScope)
            raise CephSecretException(
                f'Invalid secret scope {s!r}. Expected one of: {allowed}'
            ) from e


_TARGETED_SCOPES = frozenset((SecretScope.SERVICE, SecretScope.HOST))


class SecretURI(Protocol, Hashable):
    def to_uri(self) -> str: ...


def _q_path_component(v: str) -> str:
    return quote(v, safe='')


def _q_path(v: str) -> str:
    # CUSTOM stores a slash-delimited path in name. Preserve path separators, but
    # encode URI-reserved characters such as '?', '#', and '%'.
    return quote(v, safe='/')


def _has_empty_path_component(v: str) -> bool:
    return v.startswith('/') or v.endswith('/') or '//' in v


def _validate_components(
    *,
    uri: str,
    namespace: str,
    scope: SecretScope,
    target: str,
    name: str,
) -> None:
    if not namespace:
        raise CephSecretException(f'Invalid secret uri {uri!r}: namespace must not be empty')
    if '/' in namespace:
        raise CephSecretException(f'Invalid secret uri {uri!r}: namespace must not contain \'/\'')
    if not name:
        raise CephSecretException(f'Invalid secret uri {uri!r}: name must not be empty')

    if scope == SecretScope.GLOBAL:
        if target:
            raise CephSecretException(f'Invalid secret uri {uri!r}: target must be empty for global scope')
        if '/' in name:
            raise CephSecretException(f'Invalid secret uri {uri!r}: global secret name must not contain \'/\'')
        return

    if scope == SecretScope.CUSTOM:
        if target:
            raise CephSecretException(f'Invalid secret uri {uri!r}: target must be empty for custom scope')
        if _has_empty_path_component(name):
            raise CephSecretException(f'Invalid secret uri {uri!r}: custom path must not contain empty segments')
        return

    if scope in _TARGETED_SCOPES:
        if not target:
            raise CephSecretException(f'Invalid secret uri {uri!r}: target must not be empty')
        for label, val in (('target', target), ('name', name)):
            if '/' in val:
                raise CephSecretException(f'Invalid secret uri {uri!r}: {label} must not contain \'/\'')
        return

    raise CephSecretException(f'Invalid secret uri {uri!r}: unsupported scope {scope!r}')


@dataclass(frozen=True)
class SecretRef:
    namespace: str
    scope: SecretScope
    target: str
    name: str

    def __post_init__(self) -> None:
        try:
            scope = self.scope if isinstance(self.scope, SecretScope) else SecretScope.from_str(str(self.scope))
            object.__setattr__(self, 'scope', scope)
            _validate_components(
                uri='<SecretRef>',
                namespace=self.namespace,
                scope=scope,
                target=self.target,
                name=self.name,
            )
        except CephSecretException as e:
            raise ValueError(str(e)) from e

    def ident(self) -> Tuple[str, str, str, str]:
        return (self.namespace, self.scope.value, self.target, self.name)

    def to_uri(self) -> str:
        ns = _q_path_component(self.namespace)
        scope = self.scope.value
        if self.scope in (SecretScope.GLOBAL, SecretScope.CUSTOM):
            return f'{SECRET_SCHEME}:/{ns}/{scope}/{_q_path(self.name)}'
        return (
            f'{SECRET_SCHEME}:/{ns}/{scope}/'
            f'{_q_path_component(self.target)}/{_q_path_component(self.name)}'
        )


@dataclass(frozen=True)
class BadSecretURI:
    raw: str
    error: str
    namespace: str

    def to_uri(self) -> str:
        return self.raw


def parse_secret_uri(uri: str) -> SecretRef:
    """
    Parse a secret reference URI.

    Canonical forms:
      secret:/<namespace>/global/<name>
      secret:/<namespace>/service/<target>/<name>
      secret:/<namespace>/host/<target>/<name>
      secret:/<namespace>/custom/<any-path>
    Query strings and fragments are intentionally unsupported for now.
    """
    try:
        if not isinstance(uri, str):
            raise CephSecretException('secret uri must be a string')

        parsed = urlparse(uri)
        if parsed.scheme != SECRET_SCHEME:
            raise CephSecretException(f'Not a secret uri: {uri!r}')
        if parsed.query or parsed.fragment:
            raise CephSecretException(f'Invalid secret uri {uri!r}: query strings and fragments are not supported')

        if uri.startswith(f'{SECRET_SCHEME}://') or parsed.netloc:
            raise CephSecretException(
                f'Invalid secret uri {uri!r}: authority is not supported; '
                f'use secret:/<namespace>/<scope>/<path>'
            )

        # Canonical form: secret:/<namespace>/<scope>/<path>. Split before
        # percent-decoding so encoded slashes are never mistaken for delimiters.
        path = parsed.path or ''
        if not path.startswith('/'):
            raise CephSecretException(
                f'Invalid secret uri {uri!r}: expected secret:/<namespace>/<scope>/<path>'
            )

        namespace_raw, sep, remainder = path.lstrip('/').partition('/')
        scope_raw, sep2, rest_raw = remainder.partition('/') if sep else ('', '', '')
        if not (sep and sep2):
            raise CephSecretException(
                f'Invalid secret uri {uri!r}: expected secret:/<namespace>/<scope>/<path>'
            )

        namespace = unquote(namespace_raw)
        scope = SecretScope.from_str(unquote(scope_raw))

        if scope in (SecretScope.GLOBAL, SecretScope.CUSTOM):
            target = ''
            name = unquote(rest_raw)
        else:
            target_raw, _, name_raw = rest_raw.partition('/')
            target = unquote(target_raw)
            name = unquote(name_raw)

        # Validate with the original URI before constructing SecretRef so user-facing
        # parser errors mention the input URI rather than SecretRef's constructor context.
        _validate_components(
            uri=uri,
            namespace=namespace,
            scope=scope,
            target=target,
            name=name,
        )
        return SecretRef(namespace=namespace, scope=scope, target=target, name=name)


    except CephSecretException:
        raise
    except ValueError as e:
        raise CephSecretException(str(e)) from e
    except Exception as e:
        raise CephSecretException(f'Invalid secret uri {uri!r}: {e}') from e


def _coerce_scope(s: str) -> 'SecretScope':
    # Accept both enum values ('global') and enum names ('GLOBAL')
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
    """
    Parse a secret locator path:
      <namespace>/global/<name>
      <namespace>/service/<target>/<name>
      <namespace>/host/<target>/<name>
      <namespace>/custom/<any-path>
    """
    p = path.strip()
    if not p:
        raise CephSecretException('Invalid secret path: empty')

    if p.startswith('//'):
        raise CephSecretException(
            f"Invalid secret path {path!r}: multiple leading slashes are not allowed"
        )
    p = p.lstrip('/')

    segs = p.split('/')
    if any(s == '' for s in segs):
        raise CephSecretException(
            f"Invalid secret path {path!r}: empty segment (check for '//' or trailing '/')"
        )
    if any(s != s.strip() for s in segs):
        raise CephSecretException(
            f"Invalid secret path {path!r}: segments must not contain leading/trailing whitespace"
        )
    if len(segs) < 3:
        raise CephSecretException(
            f"Invalid secret path {path!r}. Use '<namespace>/<scope>/<path>'."
        )

    ns, scope_s = segs[0], segs[1]
    scope = _coerce_scope(scope_s)
    rest = segs[2:]

    if scope == SecretScope.GLOBAL:
        if len(rest) != 1:
            raise CephSecretException(
                f"Invalid secret path {path!r}: global scope expects '<namespace>/global/<name>'"
            )
        return ns, scope, '', rest[0]

    if scope == SecretScope.CUSTOM:
        return ns, scope, '', '/'.join(rest)

    if len(rest) != 2:
        raise CephSecretException(
            f"Invalid secret path {path!r}: {scope.value!r} scope expects "
            f"'<namespace>/{scope.value}/<target>/<name>'"
        )
    return ns, scope, rest[0], rest[1]

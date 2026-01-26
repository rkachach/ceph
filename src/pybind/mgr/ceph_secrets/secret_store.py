# -*- coding: utf-8 -*-
from collections import OrderedDict
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ceph_secrets_types import SecretScope, CephSecretException
from .secret_backend import SecretStorageBackend
import logging


logger = logging.getLogger(__name__)


SECRET_STORE_PREFIX = 'secret_store/v1/'


def _parse_ts(v: object) -> str:
    # Accept both legacy float epoch and ISO strings
    if v is None:
        return ''
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(float(v), tz=timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    if isinstance(v, str):
        # basic validation; keep as-is if it looks like ISO
        return v
    return f'Invalid timestamp type: {type(v)}'


@dataclass
class SecretRecord:
    namespace: str
    scope: SecretScope
    target: str
    name: str
    version: int
    secret_type: str
    data: Dict[str, Any]
    user_made: bool = True
    editable: bool = True
    created: str = ''
    updated: str = ''

    def ident(self) -> Tuple[str, str, str, str]:
        return (self.namespace, self.scope.value, self.target, self.name)

    def to_json(self, include_data: bool = True, include_internal: bool = False) -> Dict[str, Any]:
        d = OrderedDict([
            ('version', self.version),
            ('type', self.secret_type),
            ('created', self.created),
            ('updated', self.updated),
        ])
        if include_data:
            d['data'] = self.data
        else:
            # metadata-only: expose keys but not values
            d['keys'] = sorted(list(self.data.keys()))

        if include_internal:
            d['user_made'] = self.user_made
            d['editable'] = self.editable

        return d

    @staticmethod
    def from_json(namespace: str, scope: SecretScope, target: str, name: str, payload: Dict[str, Any]) -> 'SecretRecord':
        version = int(payload.get('version', 1))
        secret_type = str(payload.get('type', 'Opaque'))
        user_made = bool(payload.get('user_made', True))
        editable = bool(payload.get('editable', True))
        created = _parse_ts(payload.get('created', ''))
        updated = _parse_ts(payload.get('updated', ''))
        data = payload.get('data', {})
        if not isinstance(data, dict):
            raise ValueError('SecretRecord.data must be a JSON object')
        return SecretRecord(namespace, scope, target, name, version, secret_type, data, user_made, editable, created, updated)


class SecretStoreMon(SecretStorageBackend):
    """
    Mon KV-store backed secret store.

    Keys are stored under:
      secret_store/v1/<namespace>/<scope>/<target>/<secret_name>
    """

    def __init__(self, mgr: Any):
        self.mgr = mgr

    def _kv_key(self, namespace: str, scope: SecretScope, target: str, name: str) -> str:
        # Avoid '/' in components for v1 simplicity
        for label, val in (('namespace', namespace), ('name', name)):
            if '/' in val:
                raise ValueError(f"{label} must not contain '/': {val!r}")
        if scope != SecretScope.GLOBAL:
            if '/' in target:
                raise ValueError(f"target must not contain '/': {target!r}")
            return f'{SECRET_STORE_PREFIX}{namespace}/{scope.value}/{target}/{name}'
        return f'{SECRET_STORE_PREFIX}{namespace}/{scope.value}/{name}'

    def get(self, namespace: str, scope: SecretScope, target: str, name: str) -> Optional[SecretRecord]:
        k = self._kv_key(namespace, scope, target, name)
        raw = self.mgr.get_store(k)
        if raw is None:
            return None
        payload = json.loads(str(raw))
        if not isinstance(payload, dict):
            raise ValueError(f'Invalid secret payload in store for {k}')
        return SecretRecord.from_json(namespace, scope, target, name, payload)

    def set(self,
            namespace: str,
            scope: SecretScope,
            target: str,
            name: str,
            data: Dict[str, Any],
            secret_type: str = 'Opaque',
            user_made: bool = True,
            editable: bool = True) -> SecretRecord:

        existing = self.get(namespace, scope, target, name)
        if existing and not existing.editable:
            raise CephSecretException(f'Secret {name} is not editable')

        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
        if existing:
            version = existing.version + 1
            created = existing.created or now
        else:
            version = 1
            created = now
        rec = SecretRecord(
            namespace=namespace,
            scope=scope,
            target=target,
            name=name,
            version=version,
            secret_type=secret_type,
            data=data,
            user_made=user_made,
            editable=editable,
            created=created,
            updated=now,
        )
        k = self._kv_key(namespace, scope, target, name)
        v = rec.to_json(include_data=True, include_internal=True)
        self.mgr.set_store(k, json.dumps(v))
        return rec

    def rm(self, namespace: str, scope: SecretScope, target: str, name: str) -> bool:
        k = self._kv_key(namespace, scope, target, name)
        existed = self.mgr.get_store(k) is not None
        self.mgr.set_store(k, None)
        return existed

    def ls(self,
           namespace: Optional[str] = None,
           scope: Optional[SecretScope] = None,
           target: Optional[str] = None) -> List[SecretRecord]:
        # list by prefix for efficiency
        prefix = SECRET_STORE_PREFIX
        if namespace:
            prefix += f'{namespace}/'
            if scope:
                prefix += f'{scope.value}/'
                if target and scope != SecretScope.GLOBAL:
                    prefix += f'{target}/'
        items = self.mgr.get_store_prefix(prefix) or {}
        out: List[SecretRecord] = []
        for k, v in items.items():
            # k is full key: secret_store/v1/ns/scope/target/name
            suffix = k[len(SECRET_STORE_PREFIX):]
            parts = suffix.split('/')
            if len(parts) == 3:
                ns, sc, name = parts[0], parts[1], parts[2]
                tgt = ''
            elif len(parts) == 4:
                ns, sc, tgt, name = parts[0], parts[1], parts[2], parts[3]
            else:
                continue
            try:
                sc_enum = SecretScope.from_str(sc)
            except Exception:
                logger.warning("Skipping corrupted secret entry: %s (can't parse scope %s)", k, sc)
                continue
            if namespace and ns != namespace:
                continue
            if scope and sc_enum != scope:
                continue
            if target and tgt != target:
                continue
            try:
                payload = json.loads(str(v))
                if not isinstance(payload, dict):
                    continue
                out.append(SecretRecord.from_json(ns, sc_enum, tgt, name, payload))
            except Exception:
                # ignore corrupted entries but keep going
                continue
        out.sort(key=lambda r: (r.namespace, r.scope.value, r.target, r.name))
        return out

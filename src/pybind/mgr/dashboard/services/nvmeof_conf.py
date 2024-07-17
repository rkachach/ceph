# -*- coding: utf-8 -*-

import json
import logging

from orchestrator import OrchestratorError

from .. import mgr
from ..exceptions import DashboardException
from ..services.orchestrator import OrchClient

logger = logging.getLogger('nvmeof_conf')



class NvmeofGatewayAlreadyExists(Exception):
    def __init__(self, gateway_name):
        super(NvmeofGatewayAlreadyExists, self).__init__(
            "NVMe-oF gateway '{}' already exists".format(gateway_name))


class NvmeofGatewayDoesNotExist(Exception):
    def __init__(self, hostname):
        super(NvmeofGatewayDoesNotExist, self).__init__(
            "NVMe-oF gateway '{}' does not exist".format(hostname))


class ManagedByOrchestratorException(Exception):
    def __init__(self):
        super(ManagedByOrchestratorException, self).__init__(
            "NVMe-oF configuration is managed by the orchestrator")


_NVMEOF_STORE_KEY = "_nvmeof_config"


class NvmeofGatewaysConfig(object):
    @classmethod
    def _load_config_from_store(cls):
        json_db = mgr.get_store(_NVMEOF_STORE_KEY,
                                '{"gateways": {}}')
        config = json.loads(json_db)
        cls._save_config(config)
        return config

    @classmethod
    def _save_config(cls, config):
        mgr.set_store(_NVMEOF_STORE_KEY, json.dumps(config))

    @classmethod
    def get_gateways_config(cls):
        return cls._load_config_from_store()

    @classmethod
    def add_gateway(cls, name, service_url):
        config = cls.get_gateways_config()
        if name in config:
            raise NvmeofGatewayAlreadyExists(name)
        config['gateways'][name] = {'service_url': service_url}
        cls._save_config(config)

    @classmethod
    def remove_gateway(cls, name):
        config = cls.get_gateways_config()
        if name not in config['gateways']:
            raise NvmeofGatewayDoesNotExist(name)
        del config['gateways'][name]
        cls._save_config(config)

    @classmethod
    def get_service_info(cls):
        try:
            config = cls.get_gateways_config()
            service_name = list(config['gateways'].keys())[0]
            addr = config['gateways'][service_name]['service_url']
            return service_name, addr
        except (KeyError, IndexError) as e:
            raise DashboardException(
                msg=f'NVMe-oF configuration is not set: {e}',
            )

    @classmethod
    def get_client_cert(cls, service_name: str):
        client_cert = cls.from_cert_store('nvmeof_client_cert', service_name)
        return client_cert.encode() if client_cert else None

    @classmethod
    def get_client_key(cls, service_name: str):
        client_key = cls.from_cert_store('nvmeof_client_key', service_name, key=True)
        return client_key.encode() if client_key else None

    @classmethod
    def get_root_ca_cert(cls, service_name: str):
        root_ca_cert = cls.from_cert_store('nvmeof_root_ca_cert', service_name)
        # If root_ca_cert is not set, use server_cert as root_ca_cert
        return root_ca_cert.encode() if root_ca_cert else cls.get_server_cert(service_name)

    @classmethod
    def get_server_cert(cls, service_name: str):
        server_cert = cls.from_cert_store('nvmeof_server_cert', service_name)
        return server_cert.encode() if server_cert else None

    @classmethod
    def from_cert_store(cls, entity: str, service_name: str, key=False):
        try:
            orch = OrchClient.instance()
            if orch.available():
                if key:
                    return orch.cert_store.get_key(entity, service_name)
                return orch.cert_store.get_cert(entity, service_name)
            return None
        except OrchestratorError:
            # just return None if any orchestrator error is raised
            # otherwise nvmeof api will raise this error and doesn't proceed.
            return None

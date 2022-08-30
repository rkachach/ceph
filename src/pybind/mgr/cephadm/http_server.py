import cherrypy
import threading
import logging
from typing import TYPE_CHECKING

from cephadm.agent import AgentEndpoint
from cephadm.service_discovery import ServiceDiscovery


if TYPE_CHECKING:
    from cephadm.module import CephadmOrchestrator


def cherrypy_filter(record: logging.LogRecord) -> int:
    blocked = [
        'TLSV1_ALERT_DECRYPT_ERROR'
    ]
    msg = record.getMessage()
    return not any([m for m in blocked if m in msg])


logging.getLogger('cherrypy.error').addFilter(cherrypy_filter)
cherrypy.log.access_log.propagate = True


class CephadmHttpServer(threading.Thread):
    def __init__(self, mgr: "CephadmOrchestrator") -> None:
        self.mgr = mgr
        self.agent = AgentEndpoint(mgr, '::', mgr.service_discovery_port)
        self.service_discovery = ServiceDiscovery(mgr, mgr.get_mgr_ip(), mgr.service_discovery_port)
        self.cherrypy_shutdown_event = threading.Event()
        super().__init__(target=self.run)

    def configure_cherrypy(self) -> None:
        cherrypy.config.update({
            'environment': 'production',
            'engine.autoreload.on': False,
        })

    def configure(self) -> None:
        self.configure_cherrypy()
        self.agent.configure()
        self.service_discovery.configure()

    def start_server(self) -> None:
        # we only start one server, internally cherrypy
        # will attach the routes confiugred by the agent also.
        self.service_discovery.start()

    def restart(self) -> None:
        cherrypy.engine.stop()
        cherrypy.server.httpserver = None
        self.configure()
        cherrypy.engine.start()

    def run(self) -> None:
        try:
            self.mgr.log.debug('Starting cherrypy engine...')
            self.configure()
            self.start_server()
            cherrypy.server.unsubscribe()  # disable default server
            cherrypy.engine.start()
            self.mgr.log.debug('Cherrypy engine started.')
            self.mgr._kick_serve_loop()
            # wait for the shutdown event
            self.cherrypy_shutdown_event.wait()
            self.cherrypy_shutdown_event.clear()
            cherrypy.engine.stop()
            cherrypy.server.httpserver = None
            self.mgr.log.debug('Cherrypy engine stopped.')
        except Exception as e:
            self.mgr.log.error(f'Failed to run cephadm http server: {e}')

    def shutdown(self) -> None:
        self.mgr.log.debug('Stopping cherrypy engine...')
        self.cherrypy_shutdown_event.set()

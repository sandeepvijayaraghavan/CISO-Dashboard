#---------------------------------------------THREAT INTEL CODE(.py)-----------------------------------------

import json
import sys
import threading
from datetime import datetime, timezone
from logging import getLogger

from elasticsearch import Elasticsearch
from pycti import OpenCTIConnectorHelper
from scalpl import Cut

from .. import LOGGER_NAME
from .import_manager import IntelManager, StixManager
from .sightings_manager import SignalsManager

logger = getLogger(LOGGER_NAME)

TRUTHY = {"yes", "true", "True"}
FALSY = {"no", "false", "False"}


class ElasticConnector:
    def __init__(self, config: dict = {}, datadir: str = None):
        self.shutdown_event = threading.Event()
        self.helper = OpenCTIConnectorHelper(config)
        logger.info("Connected to OpenCTI")

        # Check Live Stream ID
        live_stream_id = self.helper.connect_live_stream_id
        if not live_stream_id or live_stream_id == "ChangeMe":
            raise ValueError("Missing Live Stream ID")

        self.config = Cut(config)

        # Get the external URL as configured in OpenCTI Settings
        query = """
        query SettingsQuery {
            settings {
                platform_url
            }
        }
        """
        platform_url = self.helper.api.query(query)["data"]["settings"].get("platform_url")
        self.config["opencti.platform_url"] = platform_url

        self._connect_elasticsearch()

        mode = self.config["connector.mode"]
        if mode == "ecs":
            self.import_manager = IntelManager(self.helper, self.elasticsearch, self.config, datadir)
            self.sightings_manager = SignalsManager(self.config, self.shutdown_event, self.helper, self.elasticsearch)
        elif mode == "ecs_no_signals":
            self.import_manager = IntelManager(self.helper, self.elasticsearch, self.config, datadir)
            self.sightings_manager = None
        elif mode == "stix":
            self.import_manager = StixManager(self.helper, self.elasticsearch, self.config, datadir)
            self.sightings_manager = None
        else:
            logger.error(f"Unsupported connector.mode: {mode}. Should be 'ecs', 'ecs_no_signals', or 'stix'.")

    def _connect_elasticsearch(self):
        httpauth, apikey = None, None

        cloud_auth = self.config.get("cloud.auth")
        if cloud_auth:
            httpauth = tuple(cloud_auth.split(":"))
        else:
            username = self.config.get("output.elasticsearch.username")
            password = self.config.get("output.elasticsearch.password")
            if username and password:
                httpauth = (username, password)

        api_key = self.config.get("output.elasticsearch.api_key")
        if api_key:
            apikey = tuple(api_key.split(":"))

        if httpauth and apikey:
            logger.critical("Use either username/password auth or API key auth for Elasticsearch, not both.")
            sys.exit(1)

        verify_ssl = self.config.get("output.elasticsearch.ssl_verify", "True").lower() in TRUTHY

        es_params = {
            "verify_certs": verify_ssl,
            "http_auth": httpauth,
            "api_key": apikey
        }
        if self.config.get("cloud.id"):
            es_params["cloud_id"] = self.config.get("cloud.id")
            logger.debug(f"Connecting to Elasticsearch using cloud.id {self.config.get('cloud.id')}")
        else:
            es_params["hosts"] = self.config.get("output.elasticsearch.hosts", ["localhost:9200"])
            logger.debug(f"Connecting to Elasticsearch using hosts: {es_params['hosts']}")

        self.elasticsearch = Elasticsearch(**es_params)
        logger.info("Connected to Elasticsearch")

    def handle_create(self, timestamp: datetime, data: dict):
        logger.debug(f"[CREATE] Processing indicator {data['id']}")
        self.import_manager.import_cti_event(timestamp, data)

    def handle_update(self, timestamp, data):
        logger.debug(f"[UPDATE] Processing indicator {data['id']}")
        self.import_manager.import_cti_event(timestamp, data, is_update=True)

    def handle_delete(self, timestamp, data):
        logger.debug(f"[DELETE] Processing indicator {data['id']}")
        self.import_manager.delete_cti_event(data)

    def _process_message(self, msg):
        logger.debug("_process_message")

        try:
            event_id = msg.id
            timestamp = datetime.fromtimestamp(round(int(event_id.split("-")[0]) / 1000), tz=timezone.utc)
            data = json.loads(msg.data)["data"]
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            logger.error(f"Error processing message: {e}")
            return

        logger.debug(f"[PROCESS] Message (id: {event_id}, date: {timestamp}, data: {data})")

        try:
            event_handlers = {
                "create": self.handle_create,
                "update": self.handle_update,
                "delete": self.handle_delete
            }
            event_handlers.get(msg.event, lambda *args: logger.error(f"Unknown event {msg.event}"))(timestamp, data)
        except Exception as e:
            logger.error(f"Error handling event {msg.event}: {e}")

    def start(self):
        self.shutdown_event.clear()

        if self.config["connector.mode"] == "ecs" and self.sightings_manager:
            self.sightings_manager.start()

        self.helper.listen_stream(self._process_message)

        try:
            self.shutdown_event.wait()
        except KeyboardInterrupt:
            self.shutdown_event.set()

        logger.info("Shutting down")

        if self.config["connector.mode"] == "ecs" and self.sightings_manager:
            self.sightings_manager.join(timeout=3)
            if self.sightings_manager.is_alive():
                logger.warning("Sightings manager didn't shut down by request.")

        self.elasticsearch.close()
        logger.info("Main thread complete. Waiting on background threads to complete. Press CTRL+C to quit.")


#------------------------------------------THREAT INTEL CODE (END)---------------------------------------


"""Rotating metadata-only JSON logs. No target, command, evidence or exception text."""
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


class MetadataFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({'time': self.formatTime(record), 'level': record.levelname,
                           'job_id': getattr(record, 'job_id', ''), 'state': getattr(record, 'state', '')})


def configure(path):
    logger = logging.getLogger('sentinel')
    if not logger.handlers:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(path, maxBytes=262144, backupCount=2, encoding='utf-8')
        handler.setFormatter(MetadataFormatter())
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

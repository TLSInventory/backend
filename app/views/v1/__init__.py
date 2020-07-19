from flask import Blueprint

bp = Blueprint('apiV1', __name__)

from . import misc, notification_settings, auth, sensor_collector

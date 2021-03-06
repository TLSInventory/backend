
from . import bp

from app.utils.time_helper import time_source

@bp.route('/current_timestamp', methods=['GET'])
def current_timestamp():
    return str(time_source.timestamp()), 200

import app.utils.authentication_utils
from . import bp

from app.utils.time_helper import time_source


@bp.route('/current_timestamp', methods=['GET'])
def current_timestamp():
    return str(time_source.timestamp()), 200


@bp.route('/test_jwt', methods=['GET'])
def jwt_inside_route(user_id=None):
    if user_id is None:
        user_id = app.utils.authentication_utils.get_user_id_from_jwt_or_exception()
    return str(user_id), 200

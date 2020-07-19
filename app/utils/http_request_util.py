from flask import request
from flask_limiter import Limiter

import config
# from app.db_models import logger
from app.utils.authentication_utils import get_user_id_from_current_jwt

HTTP_HEADER_CLOUDFLARE_IP_HEADER = 'CF-Connecting-IP'
HTTP_HEADER_X_REAL_IP = 'X-Real-IP'
HTTP_HEADER_X_FORWARDED_FOR = 'X-Forwarded-For'


# security: This can be easily bypassed unless whitelisting on proxy is used. Be sure to set correct settings in config.
#  This ip is also used for rate limiting, so it can have consequences.
def get_client_ip():
    if config.ServerLocation.trust_http_CF_Connecting_IP and request.headers.get(HTTP_HEADER_CLOUDFLARE_IP_HEADER):
        return request.headers.get(HTTP_HEADER_CLOUDFLARE_IP_HEADER)

    if config.ServerLocation.trust_http_X_REAL_IP and request.headers.get(HTTP_HEADER_X_REAL_IP):
        return request.headers.get(HTTP_HEADER_X_REAL_IP)

    if config.ServerLocation.trust_http_last_X_FORWARDED_FOR and request.headers.get(HTTP_HEADER_X_FORWARDED_FOR):
        try:
            return request.headers.get(HTTP_HEADER_X_FORWARDED_FOR).split(",")[-1].strip()
        except:
            # logger.warning(f'{HTTP_HEADER_X_REAL_IP}: {request.headers.get(HTTP_HEADER_X_FORWARDED_FOR)} failed split')
            pass

    # security: If none of the above headers are present and trusted, then the connecting IP is used.
    #  That is useful when there is no proxy and clients connect directly. However if there is proxy, it can lead to
    #  rate limiting the proxy as a whole. So be careful with the settings and provide and enable at least one header
    #  when using proxy.
    return request.remote_addr


def rate_limit_key():
    user_id = get_user_id_from_current_jwt()
    key = f'client_ip:{get_client_ip()}'
    if user_id:
        key = f'user_id:{user_id}'
    return key


limiter = Limiter(default_limits=[], key_func=rate_limit_key)

# todo: consider whether JSON endpoints should receive JSON response
# todo: consider scenario when attacker creates multiple accounts and uses JWT enabled endpoints for DDOS

import datetime
import logging
import os

basedir = os.path.abspath(os.path.dirname(__file__))

# warning: Do not set env vars to False, rather unset them.


class ServerLocation(object):
    address = os.environ.get('SERVER_LISTEN_ON_IP', '0.0.0.0')
    port = os.environ.get('SERVER_LISTEN_ON_PORT', 5000)
    PUBLIC_URL = os.environ.get('SERVER_PUBLIC_URL', 'http://example.com')

    # The correct determination of client IP is important for rate limiting of non-authenticated endpoints.
    # Remember that HTTP headers might be spoofed, unless nginx proxy whitelists origins.
    # If you're not sure, make GET to /api/debug/connecting_ip to check your current values.
    trust_http_CF_Connecting_IP = os.environ.get('TRUST_HTTP_CF_CONNECTING_IP') or False  # Actual HTTP header is CF-Connecting-IP
    trust_http_X_REAL_IP = os.environ.get('TRUST_HTTP_X_REAL_IP') or False  # Actual HTTP header is X-Real-IP
    trust_http_last_X_FORWARDED_FOR = os.environ.get('TRUST_HTTP_X_FORWARDED_FOR') or False  # Actual HTTP header is X-Forwarded-For


class LogConfig(object):
    log_folder = os.environ.get('LOGURU_LOG_FOLDER', 'log/')
    cors_level = logging.INFO


class FlaskConfig(object):
    START_FLASK = bool(os.environ.get("START_FLASK", False))
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(16))  # warning: autogenerating SECRET_KEY will change session on each flask restart

    DEBUG = bool(os.environ.get('DEBUG', False))

    # SQLAlchemy
    # SQLALCHEMY_DATABASE_URI = 'sqlite:///' + '../db/test.db' + "?check_same_thread = False" if DEBUG else ""
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + basedir + '/db/test.db' # + "?check_same_thread = False" if DEBUG else ""
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False

    # JWT
    JWT_TOKEN_LOCATION = ('headers', 'cookies')
    # having tokens primarily in cookies would make it easier to develop API clients. I don't want to make it default.
    # A simple change of this config should make it work and not break anything in the code.

    JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS512")
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    # if using HS512 algorithm JWT_SECRET_KEY needs to be at least 90 chars,
    # otherwise the program will be killed for security reasons.

    JWT_ACCESS_TOKEN_EXPIRES = datetime.timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = datetime.timedelta(days=40)
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = 'refresh'  # i.e. access tokens won't be revocable, only automatically expired

    JWT_REFRESH_COOKIE_PATH = "/api/v1/refreshToken"
    JWT_COOKIE_SECURE = bool(os.environ.get('JWT_COOKIE_SECURE', False if DEBUG else True))

    JWT_SESSION_COOKIE = False
    JWT_COOKIE_SAMESITE = None  # default, todo: change
    JWT_COOKIE_CSRF_PROTECT = False
    # JWT_COOKIE_DOMAIN


    # Redis
    REDIS_ENABLED = bool(os.environ.get('REDIS_ENABLED', False))
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://'


class SensorCollector(object):
    BASE_URL = os.environ.get('SENSOR_COLLECTOR_BASE_URL', 'http://flask:5000')

    GET_WORK_OVER_HTTP = bool(os.environ.get('SENSOR_COLLECTOR_GET_WORK_OVER_HTTP', False))
    PUT_WORK_TO_REDIS_JOB_QUEUE = FlaskConfig.REDIS_ENABLED and \
                                  bool(os.environ.get('SENSOR_COLLECTOR_PUT_WORK_TO_REDIS_JOB_QUEUE', False))

    SEND_RESULTS_OVER_HTTP = bool(os.environ.get('SENSOR_COLLECTOR_SEND_RESULTS_OVER_HTTP', False))
    SEND_RESULTS_TO_LOCAL_DB = bool(os.environ.get('SENSOR_COLLECTOR_SEND_RESULTS_TO_LOCAL_DB', False))

    KEY = os.environ.get('SENSOR_COLLECTOR_KEY', None)  # key is not required when the data is comming from 127.0.0.1
    KEY_SKIP_FOR_LOCALHOST = True


class DnsConfig(object):
    nameservers = ['8.8.8.8', '1.1.1.1']
    types_of_records = ['A']  #, 'AAAA']
    max_records_per_resolve = 2


class ImportConfig(object):
    crt_sh = True
    crt_sh_debug = False


class SchedulerConfig(object):
    enqueue_min_time = int(os.environ.get('MINIMUM_TIME_BETWEEN_ENQUEUING_TO_NEW_JOB', str(60*60)))  # seconds
    batch_increments = int(os.environ.get('BATCH_INCREMENTS', str(1)))  # How many Defined targets to add in each iteration. Defined target can resolve into many Scan targets when multiple IPs are ressolved by DNS.
    batch_size = int(os.environ.get('BATCH_SIZE', str(1)))  # Desired batch size of Scan targets per each scan batch. The actual upper limit will be: batch_size - batch_increments + (batch_increments * max_records_per_resolve)
    max_first_scan_delay = max(1, int(os.environ.get('FIRST_SCAN_RANDOM_DELAY', str(10))))  # seconds

    default_target_scan_periodicity = int(os.environ.get('DEFAULT_TARGET_SCAN_PERIODICITY', str(12*60*60)))  # seconds


class SslyzeConfig(object):
    asynchronous_scanning = bool(os.environ.get('SSLYZE_ASYNCHRONOUS_SCANNING', False))
    # The following parameter should be set on a sensor or wherever the scanning actually happens.
    limit_scan_to_scan_commands_names = os.environ.get("SSLYZE_LIMIT_SCANS_TO_SCAN_COMMANDS_NAMES", "DONT_LIMIT")

    # The following parameter should be set on main server and currently only works with Redis.
    # background_worker_timeout = os.environ.get('SSLYZE_BACKGROUNG_WORKER_TIMEOUT', '3m')  # https://python-rq.org/docs/jobs/
    background_worker_timeout = '5m'

    save_results_also_to_tmp_files = False
    soft_fail_on_result_parse_fail = True


class CacheConfig(object):
    enabled = bool(os.environ.get('CACHE_ENABLE', False)) and FlaskConfig.REDIS_ENABLED


class NotificationsConfig(object):
    start_sending_notifications_x_days_before_expiration = 1000  # this is currently here before better scheduler is implemented
    default_pre_expiration_periods_in_days = os.environ.get("NOTIFICATIONS_X_DAYS_BEFORE_EXPIRATION", "1,7,14")


class SlackConfig(object):
    client_id = os.environ.get("SLACK_CLIENT_ID")
    client_secret = os.environ.get("SLACK_CLIENT_SECRET")
    oauth_scope = os.environ.get("SLACK_BOT_SCOPE", "incoming-webhook")

    local_post_install_url = os.environ.get("SLACK_POST_INSTALL_URL", f'{ServerLocation.PUBLIC_URL}/api/v1/slack/auth_callback')
    slack_endpoint_url = f"https://slack.com/oauth/v2/authorize?scope={ oauth_scope }&client_id={ client_id }&redirect_uri={ local_post_install_url }"

    check_refresh_cookie_on_callback_endpoint = os.environ.get("SLACK_CHECK_REFRESH_COOKIE_ON_RETURN", False)  # can user verify slack from different device than on which he started from?


class MailConfig(object):
    enabled = bool(os.environ.get('MAIL_ENABLED') or False)

    use_gmail = bool(os.environ.get('MAIL_USE_GMAIL') or False)

    username = os.environ.get('MAIL_USERNAME') or "lorem"
    password = os.environ.get('MAIL_PASSWORD') or "ipsum"
    sender_email = os.environ.get('MAIL_SENDER_EMAIL') or username

    hostname = os.environ.get('MAIL_HOSTNAME') or "127.0.0.1"   # will be overwriten if you use gmail
    port = int(os.environ.get('MAIL_PORT', str(25)))            # will be overwriten if you use gmail
    tls = bool(os.environ.get('MAIL_TLS_ENABLED') or False)     # will be overwriten if you use gmail

    check_refresh_cookie_on_validating_email = os.environ.get("EMAIL_CHECK_REFRESH_COOKIE_ON_VALIDATION", False)  # can user verify email from different device than on which he started from?


class DebugConfig(object):
    delay_on_jwt_refresh_endpoint = os.environ.get("DEBUG_DELAY_ON_JWT_REFRESH_ENDPOINT", False)

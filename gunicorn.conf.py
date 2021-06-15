# Documentation at 
# https://github.com/benoitc/gunicorn/blob/master/examples/example_config.py

from config import ServerLocation
import time

bind = f'{ServerLocation.address}:{ServerLocation.port}'
workers = 2
timeout = 90
worker_class = 'gevent'

errorlog = '-'  # i.e. stdout
accesslog = f'log/access_log_{int(time.time())}.log'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %({x-forwarded-for}i)s'

raw_env = [
    'GUNICORN_RUNNING=True',
]

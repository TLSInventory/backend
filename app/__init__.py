import flask
from uuid import uuid4
from loguru import logger
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_marshmallow import Marshmallow
from flask_cors import CORS
import rq_dashboard
from app.utils.http_request_util import limiter
from app.utils.authentication_utils import jwt_instance, check_if_jwt_secret_key_is_too_short

import config

if config.FlaskConfig.START_FLASK:
    check_if_jwt_secret_key_is_too_short(sigkill_on_problem=True)

if config.FlaskConfig.REDIS_ENABLED:
    from redis import Redis
    import rq


db = SQLAlchemy()
ma = Marshmallow()
migrate = Migrate()

cors = CORS(resources={r"/api/*": {"origins": ["http://tlsinventory.test:8080",
                                               "http://tlsinventory.test:5000"]}},
            supports_credentials=True)


def create_app(force_create_db=False):
    import app.utils.logging_util

    app_new = Flask(__name__, instance_relative_config=True)
    app_new.config.from_object(config.FlaskConfig)

    if config.FlaskConfig.REDIS_ENABLED:
        logger.debug("RD0010 Flask is enabled - connecting to queue")
        app_new.redis = Redis.from_url(config.FlaskConfig.REDIS_URL)
        app_new.sslyze_task_queue = rq.Queue('sslyze-tasks',
                                             connection=app_new.redis,
                                             default_timeout=config.SslyzeConfig.background_worker_timeout)

    db.init_app(app_new)

    ma.init_app(app_new)
    jwt_instance.init_app(app_new)
    cors.init_app(app_new)

    with app_new.app_context():
        limiter.init_app(app_new)

        from app.views.v1 import bp as api_v1
        app_new.register_blueprint(api_v1, url_prefix='/api/v1')

        from app.views.debug import bp as api_debug
        app_new.register_blueprint(api_debug, url_prefix='/api/debug')

        from app.views.other import bp as other_routes
        app_new.register_blueprint(other_routes, url_prefix='/')

        if config.FlaskConfig.REDIS_ENABLED:
            app_new.config.from_object(rq_dashboard.default_settings)
            app_new.register_blueprint(rq_dashboard.blueprint, url_prefix='/debug/rq_dashboard/')

        @app_new.before_request
        def before_request():
            flask.request.request_id = uuid4()

        # DB creation is no longer done inside this script, and should be done using Alembic.
        # For example: export FLASK_APP=start.py && flask db upgrade
        # The exception are the tests.
        if force_create_db:
            db.create_all()

        # https://github.com/miguelgrinberg/Flask-Migrate/issues/61#issuecomment-208131722
        with app_new.app_context():
            if db.engine.url.drivername == 'sqlite':
                migrate.init_app(app_new, db, render_as_batch=True, compare_type=True)
            else:
                migrate.init_app(app_new, db)

        return app_new


import sys
import os
from typing import Optional

import flask_jwt_extended
from flask_jwt_extended import JWTManager
from werkzeug.security import generate_password_hash, check_password_hash
# werkzeug.security provides salting internally, which is amazing
import config
from loguru import logger

jwt_instance = JWTManager()


def check_if_jwt_secret_key_is_too_short(sigkill_on_problem=True):
    if config.FlaskConfig.JWT_ALGORITHM == "HS512":
        min_chars = 90
        if config.FlaskConfig.JWT_SECRET_KEY is None or len(config.FlaskConfig.JWT_SECRET_KEY) < min_chars:
            logger.exception(f"JWT_SECRET_KEY is shorter than {min_chars}. Long enough key is needed for security reasons.")
            if sigkill_on_problem:
                os.kill(os.getpid(), 9)  # sigkill
    else:
        logger.warning("Using different algorithm for JWT than HS512."
                       "Check for min key length for sufficient entropy is not implemented here.")


def hash_password(password: str) -> str:
    return generate_password_hash(str)


def check_password(known_password_hash: str, password_to_check: str) -> bool:
    return check_password_hash(known_password_hash, password_to_check)


@jwt_instance.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    return False  # todo: token is not blacklisted


def get_user_id_from_jwt(jwt) -> int:
    return jwt["id"]


def get_user_id_from_current_jwt() -> Optional[int]:
    try:
        user_jwt = flask_jwt_extended.get_jwt_identity()
        user_id = get_user_id_from_jwt(user_jwt)
        return user_id
    except:
        return None


# based on explanation at https://stackoverflow.com/a/10724898/
def jwt_refresh_token_if_check_enabled(condition):
    def decorator(func):
        if condition:
            return flask_jwt_extended.jwt_refresh_token_required(func)
        return func
    return decorator


def set_user_password(user_id: int, password: str) -> bool:
    import app.db_models as db_models
    res = db_models.db.session \
        .query(db_models.User) \
        .get(user_id)

    # todo: consider password uniqueness validation

    res.password_hash = generate_password_hash(password)
    db_models.db.session.commit()

    return True

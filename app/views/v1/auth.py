import json
import random
import jsons
from typing import Tuple

import app.utils.randomCodes as randomCodes

from config import FlaskConfig, DebugConfig
import app.utils.notifications.send as notifications_send

from . import bp

import flask
from flask import request, jsonify
from loguru import logger

import flask_jwt_extended

import app.db_schemas as db_schemas
import app.db_models as db_models
import app.utils.authentication_utils as authentication_utils


@bp.route('/login', methods=['POST'])
def api_login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)

    return action_login(username, password)


def action_login(username, password) -> Tuple[str, int]:
    USERNAME_PASSWORD_NOT_FOUND_MSG = "Bad username or password"
    msg = ""

    if not username:
        msg += "Missing username parameter. "
    if not password:
        msg += "Missing password parameter. "
    if len(msg):
        return jsonify({"msg": msg}), 400

    # todo: validate inputs based on password rules
    # todo: check password uniqueness?

    res = db_models.db.session \
        .query(db_models.User) \
        .filter(db_models.User.username == username) \
        .first()

    if res is None:
        return jsonify({"msg": USERNAME_PASSWORD_NOT_FOUND_MSG}), 401

    # todo: check bogus password even when username doesn't exist to eliminate timing attack
    res: db_models.User
    is_password_valid: bool = authentication_utils.check_password(res.password_hash, password)

    if not is_password_valid:
        return jsonify({"msg": USERNAME_PASSWORD_NOT_FOUND_MSG}), 401

    identity = {"id": res.id, "username": res.username}
    access_token = flask_jwt_extended.create_access_token(identity=identity, fresh=True)
    refresh_token = flask_jwt_extended.create_refresh_token(identity=identity)
    response_object = jsonify(access_token=access_token)
    response_object: flask.Response

    flask_jwt_extended.set_refresh_cookies(response_object, refresh_token)

    # response_object.set_cookie("refresh_token", refresh_token,
    #                            max_age=FlaskConfig.JWT_REFRESH_TOKEN_EXPIRES.total_seconds(),
    #                            secure=True, httponly=True,
    #                            domain=None,  # todo
    #                            path='/')  # todo

    return response_object, 200


@bp.route('/register', methods=['POST'])
def api_register():
    data = json.loads(request.data)
    # todo: validation
    exists_username = db_models.db.session \
        .query(db_models.User.id) \
        .filter(db_models.User.username == data["username"]) \
        .first()

    if exists_username is not None:
        return jsonify({"msg": "Username already exists"}), 400  # is there way avoid username enumeration?

    data["password_hash"] = authentication_utils.generate_password_hash(data["password"])
    data.pop("password")
    data["main_api_key"] = "API-546654-" + str(random.randrange(10000))  # todo
    logger.warning(data)

    schema = db_schemas.UserSchema(session=db_models.db)
    new_user = schema.load(data)  # this wouldn't work straight away, for example password_hash wouldn't work

    db_models.db.session.add(new_user)
    db_models.db.session.commit()

    return jsonify({"msg": "ok"}), 200


@bp.route('/refreshToken', methods=['GET'])
@flask_jwt_extended.jwt_refresh_token_required
def refresh():
    # logger.error(request.cookies)
    current_user = flask_jwt_extended.get_jwt_identity()
    # logger.error(current_user)
    access_token = flask_jwt_extended.create_access_token(identity=current_user, fresh=False)
    refresh_token = flask_jwt_extended.create_refresh_token(identity=current_user)
    response_object = jsonify(access_token=access_token)
    response_object: flask.Response

    flask_jwt_extended.set_refresh_cookies(response_object, refresh_token)

    if DebugConfig.delay_on_jwt_refresh_endpoint:
        import time
        time.sleep(10)

    return response_object, 200


@bp.route('/logout', methods=['GET'])
@flask_jwt_extended.jwt_refresh_token_required
def logout():
    access_token = "logged out"
    response_object = jsonify(access_token=access_token)
    response_object: flask.Response

    # todo: consider adding refresh cookie to blacklist

    flask_jwt_extended.unset_jwt_cookies(response_object)

    return response_object, 200


# security: place stricter rate limit
@bp.route('/user/change_password', methods=['POST'])
@flask_jwt_extended.jwt_required
def api_change_password():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    user_id = authentication_utils.get_user_id_from_current_jwt()

    old_password = request.json.get('old_password', None)
    new_password = request.json.get('new_password', None)

    res: db_models.User = db_models.db.session \
        .query(db_models.User) \
        .get(user_id)

    login_msg, login_status_code = action_login(res.username, old_password)
    if login_status_code != 200:
        return login_msg, login_status_code

    if new_password is None or len(new_password) == 0:
        return jsonify(
            {"msg": "Missing new password parameter."}), 400  # todo: consider concatenating with other error msgs

    change_ok = authentication_utils.set_user_password(res.id, new_password)
    return "ok" if change_ok else "fail", 200 if change_ok else 400


@bp.route('/user', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_get_user_profile():
    user_id = authentication_utils.get_user_id_from_current_jwt()

    res: db_models.User = db_models.db.session \
        .query(db_models.User) \
        .get(user_id)

    return jsons.dumps({
        "username": res.username,
        "main_api_key": res.main_api_key,
        "email": res.email
    }), 200


# security: place stricter rate limit
@bp.route('/user/reset_password', methods=['POST'])
def api_reset_password():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    db_code = request.json.get('db_code', None)
    new_password = request.json.get('new_password', None)

    is_code_valid, msg_or_res = randomCodes.validate_code(db_code, randomCodes.ActivityType.PASSWORD_RESET)

    if not is_code_valid:
        msg: str = msg_or_res
        return msg, 400

    res: db_models.TmpRandomCodes = msg_or_res

    if new_password is None or len(new_password) == 0:
        return jsonify(
            {"msg": "Missing new password parameter."}), 400  # todo: consider concatenating with other error msgs

    change_ok = authentication_utils.set_user_password(res.id, new_password)
    return "ok" if change_ok else "fail", 200 if change_ok else 400


@bp.route('/user/send_password_reset_email', methods=['POST'])
def api_send_password_reset_email():
    email_to_resend_validation_email_to = json.loads(request.data).get("email", "").strip()
    if len(email_to_resend_validation_email_to) == 0:
        return "No email argument provided. Aborting.", 400

    res = db_models.db.session \
        .query(db_models.User) \
        .filter(db_models.User.email == email_to_resend_validation_email_to) \
        .first()

    if res is not None:
        db_code = randomCodes.create_and_save_random_code(randomCodes.ActivityType.PASSWORD_RESET, res.id, 30)
        validation_url = f'LINK TO UI; {db_code}'  # todo: link to UI

        notifications_send.email_send_msg(email_to_resend_validation_email_to,
                                          validation_url,
                                          "Password reset for TLSInventory")

    return f'If email address belongs to existing user than an password reset email was sent to it.', 200



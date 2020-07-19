import datetime
import json
import random

import flask
import jsons
from flask import redirect

import app.utils.randomCodes as randomCodes
from config import FlaskConfig, SlackConfig, MailConfig, SensorCollector
from app.utils.http_request_util import get_client_ip, limiter
from app.utils.notifications.user_preferences import mail_add, mail_delete, list_connections_of_type, \
    get_effective_notification_settings, NotificationChannelOverride

from . import bp

from flask import request, jsonify

import flask_jwt_extended

import app.utils.db.basic as db_utils
import app.utils.db.advanced as db_utils_advanced
import app.utils.sslyze.parse_result as sslyze_parse_result
import app.scan_scheduler as scan_scheduler
from app import db_models, logger
import app.db_schemas as db_schemas
import app.utils.dns_utils as dns_utils
import app.utils.ct_search as ct_search
import app.utils.sslyze.scanner as sslyze_scanner
import app.utils.extract_test as extract_test
import app.utils.authentication_utils as authentication_utils
import app.utils.normalize_jsons as normalize_jsons
import app.object_models as object_models


@bp.route('/sslyze_get_direct_scan/<string:domain>')
def debug_sslyze_get_direct_scan(domain):
    ntwe = object_models.TargetWithExtra(db_models.Target(hostname=domain))
    res = sslyze_scanner.scan_to_json(ntwe)
    return res


@bp.route('/sslyze_batch_direct_scan', methods=['POST'])
def debug_sslyze_batch_direct_scan():
    # todo: DEPRECATED
    # logger.warning(request.data)
    data = json.loads(request.data)
    twe = []
    for x in data.get("targets", []):
        ntwe = object_models.TargetWithExtra(db_models.Target.from_repr_to_transient(x))
        twe.append(ntwe)
    res = sslyze_scanner.scan_domains_to_json(twe)
    answers = []
    for x in res:
        answers.append(json.loads(x))
    return json.dumps(answers, indent=3)


@bp.route('/sslyze_batch_scan_enqueue_redis', methods=['POST'])
def debug_sslyze_batch_scan_enqueue_redis():
    # todo: DEPRECATED
    if not SensorCollector.PUT_WORK_TO_REDIS_JOB_QUEUE:
        return "Redis support is not enabled in config", 500
    import app.utils.sslyze.background_redis as sslyze_background_redis

    # At this point I don't have access to DB (this can be run on sensor), so I can't really fully validate.
    twe = object_models.load_json_to_targets_with_extra(request.data)
    ntwe_json_list = object_models.TargetWithExtraSchema().dump(twe, many=True)
    ntwe_json_string = json.dumps(ntwe_json_list)

    return sslyze_background_redis.redis_sslyze_enqueu(ntwe_json_string), 200


@bp.route('/sslyze_batch_scan_result_redis/<string:job_id>', methods=['GET'])
def debug_sslyze_batch_scan_result_redis(job_id):
    if not SensorCollector.PUT_WORK_TO_REDIS_JOB_QUEUE:
        return "Redis support is not enabled in config", 500
    import app.utils.sslyze.background_redis as sslyze_background_redis

    job = sslyze_background_redis.redis_sslyze_fetch_job(job_id)

    return jsonify({
        'id': job.get_id(),
        'status': job.is_finished,
        'meta': job.meta,
        'result': json.loads(job.result)
    })


@bp.route('/dns_resolve_domain/<string:domain>')
def debug_dns_resolve_domain(domain):
    return jsonify({"hostname": domain, "result": dns_utils.get_ips_for_domain(domain)})


@bp.route('/ct_get_subdomains/<string:domain>')
def debug_ct_get_subdomains(domain):
    return jsonify({"hostname": domain, "result": ct_search.get_subdomains_from_ct(domain)})


@bp.route('/db_get_all')
def debug_db_get_all():
    return extract_test.test_extract_from_db()


@bp.route('/db_initialize_from_file')
def debug_db_initialize_from_file():
    sslyze_parse_result.run()
    return jsonify({})


@bp.route('/db_backdate_last_enqued')
def debug_db_backdate_last_enqued():
    res_len = scan_scheduler.backdate_enqueued_targets()
    return jsonify({"number_of_backdated_itimes": res_len})


@bp.route('/domain_to_target_string/<string:domain>')
def debug_domain_to_target_string(domain):
    # return repr(db_models.Target(hostname=domain))
    return repr(db_utils_advanced.generic_get_create_edit_from_data(db_schemas.TargetSchema,
                                                                    {'hostname': domain},
                                                                    transient_only=True)
                )


@bp.route('/scenario1', methods=['GET'])
def scenario1():
    try:
        db_models.User(username="test1", email="test1@example.com",
                       password_hash=authentication_utils.generate_password_hash("lorem"), main_api_key="aaaaa")
        db_models.Target.from_kwargs({"hostname": "borysek.eu"})

        # dt_sec = datetime.timedelta(seconds=60)

        db_models.ScanOrder.from_kwargs({"target_id": 1, "user_id": 1, "periodicity": 60})

        # date_offseted = datetime.datetime.now() - datetime.timedelta(days=10)
        # db.session.query(db_models.LastScan) \
        #     .update({db_models.LastScan.last_enqueued: date_offseted}, synchronize_session='fetch')

        db_models.db.session.commit()
    finally:
        pass
    return "done"


@bp.route('/normalizeJsons', methods=['GET'])
def scenario2():
    try:
        normalize_jsons.run()
    finally:
        pass
    return "done"


@bp.route('/loginSetRefreshCookie', methods=['GET'])
def loginSetRefreshCookie():
    identity = {"id": 1, "username": "test1"}
    refresh_token = flask_jwt_extended.create_refresh_token(identity=identity)
    response_object = jsonify({})
    flask_jwt_extended.set_refresh_cookies(response_object, refresh_token)
    return response_object, 200


@bp.route('/setAccessCookie', methods=['GET'])
@flask_jwt_extended.jwt_refresh_token_required
def debugSetAccessCookie():
    current_user = flask_jwt_extended.get_jwt_identity()
    access_token = flask_jwt_extended.create_access_token(identity=current_user, expires_delta=datetime.timedelta(days=1))
    response_object = jsonify({})
    flask_jwt_extended.set_access_cookies(response_object, access_token)
    return response_object, 200


@bp.route('/cors', methods=['GET'])
def cors1():
    return "done", 200


@bp.route('/updateTarget', methods=['GET'])
def updateTarget1():
    res = db_models.db.session \
        .query(db_models.Target) \
        .first()
    res.port = random.randint(100, 1000)
    db_models.db.session.commit()
    return "done", 200


@bp.route('/get_or_create_or_update_by_unique', methods=['GET'])
def test_get_or_create_or_update_by_unique():
    target1 = {"hostname": "lorem.borysek.eu"}
    db_utils.get_or_create_or_update_by_unique(db_models.Target, **target1)
    return "done", 200


@bp.route('/test_sending_notifications/<int:target_id>', methods=['GET'])
def test_sending_notifications(target_id):
    import app.utils.notifications.general as notifications_general
    notifications_general.schedule_notifications([target_id])
    return "done", 200


@bp.route('/send_notifications', methods=['GET'])
@bp.route('/test_notifications_scheduler', methods=['GET'])
def test_notifications_scheduler():
    import app.utils.notifications.general as notifications_general
    notifications_general.schedule_notifications()
    return "done", 200


@bp.route('/test_sslyze_simplify/', methods=['GET'])
@bp.route('/test_sslyze_simplify/<int:scan_result>', methods=['GET'])
def test_sslyze_simplify(scan_result=1):
    import app.utils.sslyze.simplify_result as sslyze_result_simplify
    res = db_models.db.session \
        .query(db_models.ScanResults) \
        .get(scan_result)
    res_simplified = sslyze_result_simplify.sslyze_result_simplify(res)
    a = db_schemas.ScanResultsSimplifiedSchema().dumps(res_simplified)

    return json.dumps(json.loads(a), indent=3), 200


@bp.route('/test_sslyze_parsing/', methods=['GET'])
def test_sslyze_parsing():
    import app.tests.sslyze_parse_test as sslyze_parse_test
    sslyze_parse_test.try_to_insert_all_scan_results()
    return "done", 200


@bp.route('/test_grading/<int:scan_result_id>', methods=['GET'])
def test_grading(scan_result_id):
    import app.utils.sslyze.grade_scan_result as grade_scan_result
    import app.utils.sslyze.simplify_result as sslyze_result_simplify

    res = db_models.db.session \
        .query(db_models.ScanResults) \
        .get(scan_result_id)

    res_simplified = sslyze_result_simplify.sslyze_result_simplify(res)
    grade_str, reasons = grade_scan_result.grade_scan_result(res, res_simplified)

    return jsonify({
        'grade': grade_str,
        'reasons': reasons
    }), 200


@bp.route('/test_sslyze_simplify_insert/<int:scan_result_id>', methods=['GET'])
def test_sslyze_simplify_insert(scan_result_id):
    import app.utils.sslyze.simplify_result as sslyze_result_simplify

    res = db_models.db.session \
        .query(db_models.ScanResults) \
        .get(scan_result_id)

    res_simplified = sslyze_result_simplify.sslyze_result_simplify(res)
    res_saved = db_utils_advanced.generic_get_create_edit_from_transient(db_schemas.ScanResultsSimplifiedSchema, res_simplified)
    return db_schemas.ScanResultsSimplifiedSchema().dumps(res_saved), 200


@bp.route('/test_recalculate_simplified/<int:scan_result_id>', methods=['GET'])
def test_recalculate_simplified(scan_result_id):
    res = db_models.db.session \
        .query(db_models.ScanResults) \
        .get(scan_result_id)

    res_saved = sslyze_parse_result.calculate_and_insert_scan_result_simplified_into_db(res)

    return db_schemas.ScanResultsSimplifiedSchema().dumps(res_saved), 200


@bp.route('/test_recalculate_simplified_all/', methods=['GET'])
def test_recalculate_simplified_all():
    res = db_models.db.session \
        .query(db_models.ScanResults.id) \
        .all()

    suc = 0

    for x in res:
        try:
            test_recalculate_simplified(x)
            suc += 1
        except Exception as e:
            logger.exception(e)

    return jsonify({'successfully': suc, 'all': len(res)}), 200


@bp.route('/test_slack2', methods=['GET'])
def test_slack2():
    import os
    slack_webhook = os.environ['SLACK_WEBHOOK']
    import app.utils.notifications.send as notifications_send
    res = notifications_send.slack_send_msg_via_webhook(slack_webhook, "test2")
    return f'{res.status}', 200 if res.ok else 400


@bp.route('/test_mail', methods=['GET'])
def test_mail1():
    import os
    mail_test_dst = os.environ['MAIL_TEST_DST']
    import app.utils.notifications.send as notifications_send
    res = notifications_send.email_send_msg(mail_test_dst, "test tlsinventory")
    return f'{res.status}', 200 if res.ok else 400


@bp.route("/slack/show_button", methods=["GET"])
def slack_pre_install():
    # This function is adopted from Slack documentation.

    return f'<a href="{SlackConfig.slack_endpoint_url}">Add to Slack</a>'


@bp.route("/slack/test_auth_to_db", methods=["GET"])
def slack_test():
    import app.utils.notifications.slack_add_connection as notifications_slack
    return notifications_slack.save_slack_config()


@bp.route('/mail_connections', methods=['GET'])
@flask_jwt_extended.jwt_required
def mail_connections():
    user_id = authentication_utils.get_user_id_from_current_jwt()
    return jsonify(list_connections_of_type(db_models.MailConnections, user_id))


@bp.route("/mail_connections/delete", methods=["DELETE"])
@bp.route("/mail_connections/add", methods=["POST"])
@flask_jwt_extended.jwt_required
def api_mail_add_or_delete():
    # this can add multiple emails at once
    user_id = authentication_utils.get_user_id_from_current_jwt()
    if request.method == "POST":
        msg, status_code = mail_add(user_id, request.json.get('emails', ""))
    if request.method == "DELETE":
        msg, status_code = mail_delete(user_id, request.json.get('emails', ""))

    return msg, status_code


@bp.route("/mail_connections/validate/<string:db_code>", methods=["GET"])
@authentication_utils.jwt_refresh_token_if_check_enabled(MailConfig.check_refresh_cookie_on_validating_email)
def mail_validate(db_code):
    # security: using the same trick as above, i.e. requiring valid refresh cookie. todo: maybe reconsider?
    user_id = authentication_utils.get_user_id_from_current_jwt()

    db_code_valid, res_or_error_msg = randomCodes.validate_code(db_code, randomCodes.ActivityType.MAIL_VALIDATION, user_id)

    if not db_code_valid:
        return res_or_error_msg, 400
    res: db_models.TmpRandomCodes = res_or_error_msg
    user_id_from_code = res.user_id
    validated_email = res.params

    mail_connection: db_models.MailConnections = db_utils_advanced.generic_get_create_edit_from_data(
        db_schemas.MailConnectionsSchema,
        {"email": validated_email, "user_id": user_id_from_code},
        get_only=True
    )
    if mail_connection is None:
        return "fail", 500
    mail_connection.validated = True
    db_models.db.session.delete(res)
    db_models.db.session.commit()
    return 'ok', 200


# security: This might leave private information in access log. Consider better option.
@bp.route('/slack_connections/<string:team_id>/<string:channel_id>', methods=['DELETE'])
@flask_jwt_extended.jwt_required
def api_slack_connection_delete(team_id: str = None, channel_id: str = None):
    user_id = authentication_utils.get_user_id_from_current_jwt()

    slack_connection: db_models.SlackConnections = db_utils_advanced.generic_get_create_edit_from_data(
        db_schemas.SlackConnectionsSchema,
        {"team_id": team_id, "channel_id": channel_id, "user_id": user_id},
        get_only=True
    )

    if slack_connection:
        db_models.db.session.delete(slack_connection)
        db_models.db.session.commit()
        return "1 deleted", 200
    return "0 deleted", 200


@bp.route('/slack_connections', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_slack_connections_get():
    user_id = authentication_utils.get_user_id_from_current_jwt()
    return jsonify(list_connections_of_type(db_models.SlackConnections, user_id))



@bp.route('/connecting_ip', methods=['GET'])
def debug_connecting_ip():
    return jsonify({
        "CF-Connecting-IP": request.headers.get("CF-Connecting-IP"),
        "X-Forwarded-For": request.headers.get("X-Forwarded-For"),
        "X-Real-IP": request.headers.get("X-Real-IP"),
        "presumed_original_ip": get_client_ip()
    }), 200


@bp.route('/rate_limit_ip', methods=['GET'])
@limiter.limit("1/second")
def debug_test_rate_limit_ip():
    return "ok", 200


@bp.route('/notification_connections', methods=['GET'])
@bp.route('/notification_connections/<string:target_id>', methods=['GET'])
@flask_jwt_extended.jwt_required
def show_notification_connections(target_id=None):
    user_id = authentication_utils.get_user_id_from_current_jwt()
    connection_lists = get_effective_notification_settings(user_id, target_id)
    return jsonify(connection_lists)


@bp.route('/url_map', methods=['GET'])
def debug_url_map():
    a = flask.current_app.url_map
    # b = flask.url_for("apiDebug.mail_validate", db_code="teasd", _external=True)
    return str(a)


@bp.route('/current_app', methods=['GET'])
def current_app():
    a = flask.current_app
    return str(a)


@bp.route('/test_jsons', methods=['POST'])
def test_jsons():
    data = jsons.loads(request.data, NotificationChannelOverride)
    return jsons.dumps(data), 200
import copy
import datetime
import json
import random
from typing import List

from flask import redirect

import app.object_models as object_models
import app.utils.ct_search as ct_search
import app.utils.sslyze.simplify_result as sslyze_result_simplify

from app.utils.notifications.user_preferences import get_effective_notification_settings, mail_add

from app.utils.notifications.actions import set_notification_settings_raw_multiple_target_ids

from . import bp

from flask import request, jsonify
from loguru import logger

import flask_jwt_extended

import app.utils.db.basic as db_utils
import app.utils.db.advanced as db_utils_advanced
import app.db_schemas as db_schemas
import app.db_models as db_models
import app.utils.authentication_utils as authentication_utils
import app.actions as actions
import app.actions.sensor_collector as sensor_collector
import app.views.v1.notification_settings as slack_url_to_oauth
import app.utils.randomCodes as randomCodes
from config import SlackConfig


@bp.route('/get_target_id_from_definition', methods=['POST'])
@flask_jwt_extended.jwt_required
def get_target_id(target_def=None):
    if target_def:
        data = target_def
    else:
        data = json.loads(request.data)
    # logger.warning(data)
    data["protocol"] = data.get("protocol", "HTTPS").replace("TlsWrappedProtocolEnum.", "")  # todo: remove this hack
    target = db_utils_advanced.generic_get_create_edit_from_data(db_schemas.TargetSchema, data, get_only=True)
    if not target:
        return "fail", 400
    user_id = authentication_utils.get_user_id_from_current_jwt()

    # validate that the user entered the target definition at least once. Protection against enumaration attack.
    if not actions.can_user_get_target_definition_by_id(target.id, user_id):
        return "fail", 400
    return jsonify({"id": target.id}), 200


@bp.route('/target/<int:target_id>', methods=['GET', 'DELETE'])
@flask_jwt_extended.jwt_required
def api_target_by_id(target_id: int):
    user_id = authentication_utils.get_user_id_from_current_jwt()

    target = actions.get_target_from_id_if_user_can_see(target_id, user_id)
    if target is None:
        return "Target either doesn't exist or you're allowed to see it.", 400

    if request.method == 'DELETE':
        scan_order: db_models.ScanOrder = db_utils_advanced.generic_get_create_edit_from_data(
            db_schemas.ScanOrderSchema,
            {"target_id": target.id, "user_id": user_id},
            get_only=True
        )
        scan_order.active = False
        db_models.db.session.commit()
        db_utils.actions_on_modification(scan_order)

    scan_order = db_utils_advanced.generic_get_create_edit_from_data(db_schemas.ScanOrderSchema,
                                                                     {"target_id": target.id, "user_id": user_id},
                                                                     get_only=True)

    notifications = get_effective_notification_settings(user_id, target_id)

    return jsonify(actions.full_target_settings_to_dict(target, scan_order, notifications))


def additional_channel_email_actions(email_pref: dict, user_id: int) -> bool:
    ADD_NEW_EMAILS_FIELD = "add_new_emails"

    emails_to_be_added = getattr(email_pref, ADD_NEW_EMAILS_FIELD, None)
    if emails_to_be_added:
        try:
            new_mails_or_exception_msg, status_code = mail_add(user_id, emails_to_be_added)
            if status_code != 200:
                raise Exception(new_mails_or_exception_msg)
            delattr(email_pref, ADD_NEW_EMAILS_FIELD)

            new_emails_ids_to_force_enable = [x.id for x in new_mails_or_exception_msg]
            email_pref.force_enabled_ids.extend(new_emails_ids_to_force_enable)
        except Exception as e:
            logger.error(f"Error adding new emails for target: {e}")
            return False

    return True


@bp.route('/add_targets', methods=['POST', 'PUT'])
@bp.route('/add_target', methods=['POST', 'PUT'])
@bp.route('/target', methods=['PUT', 'PATCH'])
@flask_jwt_extended.jwt_required
def api_target():
    user_id = authentication_utils.get_user_id_from_current_jwt()

    data = json.loads(request.data)
    data["target"]["protocol"] = data.get("protocol", "HTTPS").replace("TlsWrappedProtocolEnum.",
                                                                       "")  # todo: remove this hack
    data["target"].pop("id", None)

    target_hostnames = data["target"]["hostname"].split(";")
    target_hostnames = list(map(lambda x: x.strip(), target_hostnames))
    target_hostnames = list(filter(lambda x: len(x), target_hostnames))
    target_hostnames = list(set(target_hostnames))

    target_ids = set()

    for target_hostname in target_hostnames:
        new_target_def = copy.deepcopy(data["target"])
        new_target_def["hostname"] = target_hostname

        target = db_utils_advanced.generic_get_create_edit_from_data(db_schemas.TargetSchema, new_target_def)

        target_ids.add(target.id)

        if data.get("scanOrder"):
            scan_order_def = db_utils.merge_dict_with_copy_and_overwrite(data.get("scanOrder", {}),
                                                                         {"target_id": target.id, "user_id": user_id})
            db_utils_advanced.generic_get_create_edit_from_data(db_schemas.ScanOrderSchema, scan_order_def)

    if data.get("notifications"):
        set_notification_settings_raw_multiple_target_ids(user_id, target_ids, data.get("notifications"))

    return f'Inserted {len(target_ids)} targets', 200
    # return api_target_by_id(target.id)  # todo: reenable this


@bp.route('/add_scan_order', methods=['POST'])
@flask_jwt_extended.jwt_required
def api_add_scan_order():
    data = json.loads(request.data)
    schema = db_schemas.ScanOrderSchema(session=db_models.db)
    # todo deduplicate
    # todo validation
    data["user_id"] = random.randrange(100000)  # todo: make dynamic (from server side)
    result = schema.load(data)
    db_models.db.session.add(result)
    db_models.db.session.commit()
    db_utils.actions_on_modification(result)
    return repr(result)


@bp.route('/enable_target_scan/<int:target_id>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_enable_target_scan(target_id: int):
    user_id = authentication_utils.get_user_id_from_current_jwt()

    target = actions.get_target_from_id_if_user_can_see(target_id, user_id)
    if target is None:
        return "Target either doesn't exist or you're allowed to see it.", 400

    scan_order: db_models.ScanOrder = db_utils_advanced.generic_get_create_edit_from_data(
        db_schemas.ScanOrderSchema,
        {"target_id": target.id, "user_id": user_id},
        get_only=True
    )
    scan_order.active = True
    db_models.db.session.commit()
    db_utils.actions_on_modification(scan_order)
    return "ok", 200


@bp.route('/get_user_targets')
@flask_jwt_extended.jwt_required
def api_get_user_targets():
    user_id = authentication_utils.get_user_id_from_current_jwt()

    res = db_models.db.session \
        .query(db_models.ScanOrder, db_models.Target, db_models.LastScan, db_models.ScanResults,
               db_models.ScanResultsSimplified) \
        .outerjoin(db_models.ScanResults, db_models.LastScan.result_id == db_models.ScanResults.id) \
        .outerjoin(db_models.ScanResultsSimplified,
                   db_models.ScanResultsSimplified.scanresult_id == db_models.ScanResults.id) \
        .filter(db_models.LastScan.target_id == db_models.Target.id) \
        .filter(db_models.ScanOrder.target_id == db_models.Target.id) \
        .filter(db_models.ScanOrder.user_id == user_id) \
        .all()

    # res: List[Tuple[db_models.ScanOrder, db_models.Target, db_models.LastScan, db_models.ScanResults]]

    schema = db_schemas.TargetSchema(many=True)
    json_dict = schema.dump([x.Target for x in res])

    for obj in json_dict:
        for single_res in res:
            if obj["id"] == single_res.Target.id:
                obj["active"] = 'yes' if single_res.ScanOrder.active else 'no'

                obj["expires"] = "Not scanned yet"
                obj["grade"] = "Not scanned yet"
                if single_res.ScanResults is None:
                    continue

                if single_res.ScanResultsSimplified:
                    scan_result_simplified = single_res.ScanResultsSimplified
                else:
                    scan_result_simplified = sslyze_result_simplify.sslyze_result_simplify(single_res.ScanResults)
                    # todo: consider saving the simplified result

                if scan_result_simplified:
                    if isinstance(single_res.ScanResultsSimplified.notAfter, int):
                        obj["expires"] = str(datetime.datetime.fromtimestamp(single_res.ScanResultsSimplified.notAfter))
                    obj["grade"] = single_res.ScanResultsSimplified.grade
                    obj["grade_reasons"] = single_res.ScanResultsSimplified.grade_reasons
                    continue

    # for x in json_dict:
    #     x["grade"] = random.choice([chr(ord('A')+i) for i in range(5)])
    #     x["expires"] = datetime.date(2020, 1, 1) + datetime.timedelta(days=random.randint(10, 500))

    json_string = json.dumps(json_dict, default=str)
    # logger.debug(json_string)
    return json_string, 200


@bp.route('/sslyze_scan_targets', methods=['POST'])
@flask_jwt_extended.jwt_required
def api_sslyze_scan_targets():
    twe = object_models.load_json_to_targets_with_extra(request.data)
    scan_result = actions.sslyze_scan(twe)
    sensor_collector.sslyze_save_scan_results(scan_result)
    return scan_result, 200


@bp.route('/get_result_for_target/<int:target_id>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_get_result_for_target(target_id):
    user_id = authentication_utils.get_user_id_from_current_jwt()

    last_scan, scan_result = actions.get_last_scan_and_result(target_id, user_id)
    last_scan: db_models.LastScan
    scan_result: db_models.ScanResults

    if scan_result is None:
        return "Target either doesn't exist or the current user doesn't have permission to view it.", 401

    last_scanned = last_scan.last_scanned
    last_scanned_datetime = db_models.timestamp_to_datetime(last_scanned)

    scan_result_str = db_schemas.ScanResultsSchema().dumps(scan_result)

    return jsonify({'result': json.loads(scan_result_str), 'time': last_scanned_datetime}), 200


@bp.route('/get_basic_cert_info_for_target/<int:target_id>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_get_basic_cert_info_for_target(target_id):
    user_id = authentication_utils.get_user_id_from_current_jwt()

    last_scan, scan_result = actions.get_last_scan_and_result(target_id, user_id)
    last_scan: db_models.LastScan
    scan_result: db_models.ScanResults

    if scan_result is None:
        return "Target either doesn't exist or the current user doesn't have permission to view it.", 401

    last_scanned_datetime = db_models.timestamp_to_datetime(last_scan.last_scanned)
    cert_info = scan_result.certificate_information
    verified_chain = cert_info.verified_certificate_chain_list
    certificates_in_chain: List[db_models.Certificate] = db_models.Certificate.select_from_list(verified_chain.chain)

    list_cert = certificates_in_chain[0]

    return {'chain_notBefore': max([x.notBefore for x in certificates_in_chain]),
            'chain_notAfter': min([x.notAfter for x in certificates_in_chain]),
            'leaf_sni': list_cert.subject_alternative_name_list,
            'leaf_subject': list_cert.subject,
            'information_fetched_on': last_scanned_datetime
            }, 200


@bp.route('/scan_result_history', methods=['GET'])
@bp.route('/scan_result_history/<int:x_days>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_scan_result_history(user_id=None, x_days=30):
    if user_id is None:
        user_id = authentication_utils.get_user_id_from_current_jwt()

    res = actions.get_scan_history(user_id, x_days)

    if res is None:
        return "[]", 200

    res_arr = []
    for x in res:
        new_dict = {
            "timestamp": None,
            "target": None,
            "result_simplified": None,
        }
        if x.ScanResultsHistory:
            new_dict["timestamp"] = x.ScanResultsHistory.timestamp
        new_dict["target"] = json.loads(db_schemas.TargetSchema().dumps(x.Target))
        new_dict["result_simplified"] = json.loads(
            db_schemas.ScanResultsSimplifiedSchema().dumps(x.ScanResultsSimplified))
        res_arr.append(new_dict)

    return json.dumps(res_arr, indent=3), 200


@bp.route('/ct_get_subdomains/<string:domain>')
def api_ct_get_subdomains(domain):
    return jsonify({"hostname": domain, "result": ct_search.get_subdomains_from_ct(domain)})


@bp.route("/slack/begin_auth_redirect", methods=["GET"])
@flask_jwt_extended.jwt_required
def slack_redirect_to_oauth():
    url, _ = slack_url_to_oauth()
    return redirect(url, code=302)


@bp.route("/slack/auth_callback", methods=["GET", "POST"])
@authentication_utils.jwt_refresh_token_if_check_enabled(SlackConfig.check_refresh_cookie_on_callback_endpoint)
def slack_oauth_callback():
    # security: It's not possible to get here Access token. (This requests comes from users browser after redirect from
    #  Slack. Refresh token should be in cookies, but that might make problems with API calls. It's dificult to say what
    #  should be the correct behaviour. For now I'll lock it down so that the following scenario is not possible.
    #  Scenario:
    #       - Attacker generates URL using endpoint slack_redirect_to_oauth. He sends it to victim.
    #       - Victim fills out the Slack authorization form and submits it.
    #       - Attacker gets the access because he is the one who initiated the request.
    #  Now replace the work Attacker with Employee and it sounds like legit scenario.
    #  Current behaviour: The slack_redirect_to_oauth and slack_oauth_callback need to be initiated by the same user.
    #                     The slack_oauth_callback expects refresh token in cookie, can be disabled in config.

    user_id = None
    if SlackConfig.check_refresh_cookie_on_callback_endpoint:
        user_id = authentication_utils.get_user_id_from_current_jwt()

    auth_code = request.args['code']
    db_code = request.args['state']

    db_code_valid, res_or_error_msg = randomCodes.validate_code(db_code, randomCodes.ActivityType.SLACK, user_id)

    if not db_code_valid:
        return res_or_error_msg, 400
    res: db_models.TmpRandomCodes = res_or_error_msg

    import app.utils.notifications.slack_add_connection as notifications_slack
    ok = notifications_slack.validate_code_and_save(auth_code, res.user_id)
    if ok:
        return 'OK. Window will close in 2 seconds. <script>setTimeout(function(){ close() }, 2000);</script>', 200
    return 'fail', 500


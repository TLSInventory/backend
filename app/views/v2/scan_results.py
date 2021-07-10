from typing import List

import app.views.v1.misc
import app.db_models as db_models
from . import bp

from flask import request, jsonify
from loguru import logger

import flask_jwt_extended

import app.db_schemas as db_schemas
import app.utils.authentication_utils as authentication_utils
import app.actions as actions


def get_user_targets_only(user_id: int) -> dict:
    res = db_models.db.session \
        .query(db_models.ScanOrder, db_models.Target) \
        .filter(db_models.ScanOrder.target_id == db_models.Target.id) \
        .filter(db_models.ScanOrder.user_id == user_id) \
        .all()

    schema = db_schemas.TargetSchema(many=True)
    json_dict = schema.dump([x.Target for x in res])

    assert len(res) == len(json_dict), "ERROR - Current implementation relies on having the same len for two fields"
    for i in range(len(res)):
        json_dict[i]["active"] = 'yes' if res[i].ScanOrder.active else 'no'

    return json_dict


@bp.route('/history/scans_timeline', methods=['GET'])
@bp.route('/history/scans_timeline/<int:x_days>', methods=['GET'])
def api_scan_result_history_without_certs(user_id=None, x_days=30):
    if user_id is None:
        user_id = authentication_utils.get_user_id_from_jwt_or_exception()

    res = actions.get_scan_history(user_id, x_days)

    if res is None:
        return "[]", 200

    server_info_schema = db_schemas.ServerInfoSchemaWithoutCiphers()

    res_dict = {}
    for x in res:
        try:
            res_dict[x.ScanResultsHistory.id] = {
                "timestamp": x.ScanResultsHistory.timestamp,
                "server_info": server_info_schema.dump(x.ServerInfo),
                "target_id": x.Target.id,
                "scan_result_id": x.ScanResultsSimplified.scanresult_id if x.ScanResultsSimplified else None,
            }
        except Exception as e:
            logger.error(f"{x} | {e}")
            raise

    return jsonify(res_dict)


@bp.route('/history/scan_results_simplified', methods=['GET'])
@bp.route('/history/scan_results_simplified/<int:x_days>', methods=['GET'])
def api_get_users_scan_results_simplified(user_id=None, x_days=30):
    if user_id is None:
        user_id = authentication_utils.get_user_id_from_jwt_or_exception()

    res = actions.get_scan_history(user_id, x_days)

    if res is None:
        return "[]", 200

    scan_results_simplified = list(map(lambda x: x.ScanResultsSimplified, res))
    scan_results_simplified2 = list(filter(lambda x: x, scan_results_simplified))
    res2: List[dict] = db_schemas.ScanResultsSimplifiedWithoutCertsSchema().dump(scan_results_simplified2, many=True)
    res_dict_of_dicts = db_schemas.convert_arr_of_dicts_to_dict_of_dicts(res2)
    return jsonify(res_dict_of_dicts)


@bp.route('/history/certificate_chains', methods=['GET'])
@bp.route('/history/certificate_chains/<int:x_days>', methods=['GET'])
def api_get_users_certificate_chains(user_id=None, x_days=30):
    if user_id is None:
        user_id = authentication_utils.get_user_id_from_jwt_or_exception()

    res = actions.get_certificate_chains(user_id, x_days)
    res_dicts: List[dict] = db_schemas.CertificateChainSchemaWithoutCertificates().dump(res, many=True)
    res_dict_of_dicts = db_schemas.convert_arr_of_dicts_to_dict_of_dicts(res_dicts)
    return jsonify(res_dict_of_dicts)


@bp.route('/history/certificates', methods=['GET'])
@bp.route('/history/certificates/<int:x_days>', methods=['GET'])
def api_get_users_certificates(user_id=None, x_days=30):
    if user_id is None:
        user_id = authentication_utils.get_user_id_from_jwt_or_exception()

    # logger.debug("Start getting certificate chains")
    res_chains = actions.get_certificate_chains(user_id, x_days)

    # logger.debug("Start getting certificates")
    res_certs = actions.get_certificates(res_chains)

    # logger.debug("Start serializing certificates")
    res_dicts: List[dict] = db_schemas.CertificateSchema().dump(res_certs, many=True)
    res_dict_of_dicts = db_schemas.convert_arr_of_dicts_to_dict_of_dicts(res_dicts)
    return jsonify(res_dict_of_dicts)


def convert_scan_results_to_v1(a, b, c, d, e) -> List[dict]:
    for chain_key in c:
        c[chain_key]["certificate_chain"] = [d[str(x)] for x in c[chain_key]["chain_arr"]]

    for scan_result_id in b:
        received_certificate_chain_list_id = b[scan_result_id].get("received_certificate_chain_list_id")
        if received_certificate_chain_list_id:
            b[scan_result_id]["received_certificate_chain_list"] = c[str(received_certificate_chain_list_id)]

        b[scan_result_id]["verified_certificate_chains_list"] = [c[str(x)] for x in b[scan_result_id]["verified_certificate_chains_lists_ids_arr"]]

    # logger.debug(e)

    e_dict = db_schemas.convert_arr_of_dicts_to_dict_of_dicts(e)

    for single_scan_attempt_id in a:
        # logger.warning(a[single_scan_attempt_id])
        scan_result_id = a[single_scan_attempt_id]["scan_result_id"]
        if scan_result_id:
            a[single_scan_attempt_id]["result_simplified"] = b[str(scan_result_id)]

        target_id = a[single_scan_attempt_id]["target_id"]
        a[single_scan_attempt_id]["target"] = e_dict[target_id]
        pass

    new_res = []
    for single_scan_attempt_id in a:
        new_res.append(a[single_scan_attempt_id])

    return new_res


@bp.route('/history/scan_results', methods=['GET'])
@bp.route('/history/scan_results/<int:x_days>', methods=['GET'])
def api_scan_results_history_v2(user_id=None, x_days=30):
    if user_id is None:
        user_id = authentication_utils.get_user_id_from_jwt_or_exception()

    logger.debug("before API requests")
    a = api_scan_result_history_without_certs(user_id, x_days).json
    b = api_get_users_scan_results_simplified(user_id, x_days).json
    c = api_get_users_certificate_chains(user_id, x_days).json
    d = api_get_users_certificates(user_id, x_days).json
    e = get_user_targets_only(user_id)
    logger.debug("after API requests")

    new_res = convert_scan_results_to_v1(a, b, c, d, e)
    new_res_2 = sorted(new_res, key=lambda x: x["timestamp"])

    logger.debug("after conversion of scan_results for backwards compatibility")
    # return json.dumps(sorted(new_res, key=lambda x: x["timestamp"]), indent=4, sort_keys=True), 200
    return jsonify(new_res_2)


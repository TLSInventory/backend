from typing import List

import app.db_schemas
from . import bp

from flask import request, jsonify
from loguru import logger

import flask_jwt_extended

import app.db_schemas as db_schemas
import app.utils.authentication_utils as authentication_utils
import app.actions as actions


@bp.route('/history/scans_timeline', methods=['GET'])
@bp.route('/history/scans_timeline/<int:x_days>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_scan_result_history_without_certs(user_id=None, x_days=30):
    if user_id is None:
        user_id = authentication_utils.get_user_id_from_current_jwt()

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
@flask_jwt_extended.jwt_required
def api_get_users_scan_results_simplified(user_id=None, x_days=30):
    if user_id is None:
        user_id = authentication_utils.get_user_id_from_current_jwt()

    res = actions.get_scan_history(user_id, x_days)

    if res is None:
        return "[]", 200

    scan_results_simplified = list(map(lambda x: x.ScanResultsSimplified, res))
    res2: List[dict] = db_schemas.ScanResultsSimplifiedWithoutCertsSchema().dump(scan_results_simplified, many=True)
    res_dict_of_dicts = app.db_schemas.convert_arr_of_dicts_to_dict_of_dicts(res2)
    return jsonify(res_dict_of_dicts)


@bp.route('/history/certificate_chains', methods=['GET'])
@bp.route('/history/certificate_chains/<int:x_days>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_get_users_certificate_chains(user_id=None, x_days=30):
    if user_id is None:
        user_id = authentication_utils.get_user_id_from_current_jwt()

    res = actions.get_certificate_chains(user_id, x_days)
    res_dicts: List[dict] = db_schemas.CertificateChainSchemaWithoutCertificates().dump(res, many=True)
    res_dict_of_dicts = app.db_schemas.convert_arr_of_dicts_to_dict_of_dicts(res_dicts)
    return jsonify(res_dict_of_dicts)


@bp.route('/history/certificates', methods=['GET'])
@bp.route('/history/certificates/<int:x_days>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_get_users_certificates(user_id=None, x_days=30):
    if user_id is None:
        user_id = authentication_utils.get_user_id_from_current_jwt()

    # logger.debug("Start getting certificate chains")
    res_chains = actions.get_certificate_chains(user_id, x_days)

    # logger.debug("Start getting certificates")
    res_certs = actions.get_certificates(res_chains)

    # logger.debug("Start serializing certificates")
    res_dicts: List[dict] = db_schemas.CertificateSchema().dump(res_certs, many=True)
    res_dict_of_dicts = app.db_schemas.convert_arr_of_dicts_to_dict_of_dicts(res_dicts)
    return jsonify(res_dict_of_dicts)

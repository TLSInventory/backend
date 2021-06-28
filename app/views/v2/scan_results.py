from typing import List

import app.db_schemas
from . import bp

from flask import request, jsonify
from loguru import logger

import flask_jwt_extended

import app.db_schemas as db_schemas
import app.utils.authentication_utils as authentication_utils
import app.actions as actions


@bp.route('/certificate_chains', methods=['GET'])
@bp.route('/certificate_chains/<int:x_days>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_get_users_certificate_chains(user_id=None, x_days=30):
    if user_id is None:
        user_id = authentication_utils.get_user_id_from_current_jwt()

    res = actions.get_certificate_chains(user_id, x_days)
    res_dicts: List[dict] = db_schemas.CertificateChainSchemaWithoutCertificates().dump(res, many=True)
    res_dict_of_dicts = app.db_schemas.convert_arr_of_dicts_to_dict_of_dicts(res_dicts)
    return jsonify(res_dict_of_dicts)


@bp.route('/certificates', methods=['GET'])
@bp.route('/certificates/<int:x_days>', methods=['GET'])
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

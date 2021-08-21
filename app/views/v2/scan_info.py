from typing import Tuple, List

import json
import app.db_models as db_models
import app.actions as actions
import app.utils.authentication_utils as authentication_utils

from . import bp

@bp.route('/get_general_scan_info', methods=['GET'])
def get_general_scan_info() -> Tuple[int, str]:
    return create_info_dict_from_list(
        db_models.db.session.query(db_models.ScanResultsSimplified).all()
    )

@bp.route('/get_user_scan_info', methods=['GET'])
def get_user_scan_info(user_id=None, days_back=30):
    if user_id is None:  # this way I can test with built DB and do not have to wait fo scans to finish
        user_id = authentication_utils.get_user_id_from_jwt_or_exception()

    user_scan_history = actions.get_scan_history(user_id, days_back)

    if user_scan_history is None:
        return "[]", 200

    user_scan_results_simplified_partial = list(
        map(lambda x: x.ScanResultsSimplified, user_scan_history)
    )
    user_scan_results_simplified = list(
        filter(lambda x: x, user_scan_results_simplified_partial)
    )
    return create_info_dict_from_list(list(user_scan_results_simplified))


def create_info_dict_from_list(
    scan_results: List[db_models.ScanResultsSimplified]
):
    out = {
        "scan_count": len(scan_results),
        "protocol_support": {},
        "heartbleed": 0,
        "ccs_injection": 0,
        "downgrade": 0
    }

    for scan_result in scan_results:
        update_info_dict_from_object(scan_result, out)

    return 200, json.dumps(out)


def update_info_dict_from_object(
    scan_result: db_models.ScanResultsSimplified, out
):
    # protocol support
    support = (
        scan_result.sslv2_working_ciphers_count,
        scan_result.sslv3_working_ciphers_count,
        scan_result.tlsv10_working_ciphers_count,
        scan_result.tlsv11_working_ciphers_count,
        scan_result.tlsv12_working_ciphers_count,
        scan_result.tlsv13_working_ciphers_count,
    )

    for protocol, support in zip(
        ("sslv2", "sslv3", "tlsv10", "tlsv11", "tlsv12", "tlsv13"), support
    ):
        if support:
            out["protocol_support"][protocol] = out["protocol_support"].get(protocol, 0) + 1
            break

    # vulnerabilities
    complete_scan_result = db_models.db.session.query(
        db_models.ScanResults
    ).get(scan_result.scanresult_id)

    if complete_scan_result.openssl_ccs_injection is not None and \
            complete_scan_result.openssl_ccs_injection.is_vulnerable_to_ccs_injection:
        out["ccs_injection"] += 1
    if complete_scan_result.openssl_heartbleed is not None and \
            complete_scan_result.openssl_heartbleed.is_vulnerable_to_heartbleed:
        out["heartbleed"] += 1
    if complete_scan_result.downgrade_attacks is not None and \
            not complete_scan_result.downgrade_attacks.supports_fallback_scsv:
        out["downgrade"] += 1

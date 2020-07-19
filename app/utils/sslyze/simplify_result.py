from typing import Optional

import app.db_models as db_models
import app.utils.db.basic as db_utils
from loguru import logger
import app.utils.sslyze.grade_scan_result as grade_scan_result


def count_after_split_of_param_if_not_none(x: Optional[object], param_name: str) -> Optional[int]:
    if x is None:
        return None  # This is not ideal, but does is probably better than 0
    return len(db_utils.split_array_to_tuple(getattr(x, param_name)))


# todo: maybe persist to DB?
def sslyze_result_simplify(scan_result: db_models.ScanResults) -> db_models.ScanResultsSimplified:
    simple = db_models.ScanResultsSimplified()
    simple.scanresult_id = scan_result.id

    if not scan_result.certificate_information:
        logger.info(f"Simplifing scan result ({scan_result.id}) which doesn't have certificate_information")
    else:
        simple.received_certificate_chain_list_id = scan_result.certificate_information.received_certificate_chain_list_id

        trust_stores = set()
        certificate_chains_that_were_verified_ids = set()

        verified_chain_list = scan_result.certificate_information.verified_certificate_chain_list
        received_chain_list = scan_result.certificate_information.received_certificate_chain_list

        if verified_chain_list:
            res_new = db_models.db.session \
                .query(db_models.ValidatedPath) \
                .filter(db_models.ValidatedPath.chain_id == verified_chain_list.id) \
                .all()
            # .filter(db_models.ValidatedPath.chain_id.in_(changed_targets)) \

            for sr in res_new:
                sr: db_models.ValidatedPath
                trust_stores.add(sr.trust_store.name)
                certificate_chains_that_were_verified_ids.add(str(sr.chain.id))

        simple.validated_against_truststores_list = ", ".join(list(trust_stores))
        simple.verified_certificate_chains_lists_ids = ", ".join(list(certificate_chains_that_were_verified_ids))

        chain_for_dates = verified_chain_list if verified_chain_list else received_chain_list

        if chain_for_dates:
            simple.notAfter = db_models.datetime_to_timestamp(chain_for_dates.not_after())
            simple.notBefore = db_models.datetime_to_timestamp(chain_for_dates.not_before())

    simple.sslv2_working_ciphers_count = count_after_split_of_param_if_not_none(scan_result.sslv2, "accepted_cipher_list")
    simple.sslv3_working_ciphers_count = count_after_split_of_param_if_not_none(scan_result.sslv3, "accepted_cipher_list")
    simple.tlsv10_working_ciphers_count = count_after_split_of_param_if_not_none(scan_result.tlsv1, "accepted_cipher_list")
    simple.tlsv11_working_ciphers_count = count_after_split_of_param_if_not_none(scan_result.tlsv11, "accepted_cipher_list")
    simple.tlsv12_working_ciphers_count = count_after_split_of_param_if_not_none(scan_result.tlsv12, "accepted_cipher_list")
    simple.tlsv13_working_ciphers_count = count_after_split_of_param_if_not_none(scan_result.tlsv13, "accepted_cipher_list")

    grade, grade_cap_reasons = grade_scan_result.grade_scan_result(scan_result, simple)
    simple.grade = grade
    simple.grade_reasons = ", ".join(grade_cap_reasons)

    # todo: maybe persist to DB?
    return simple

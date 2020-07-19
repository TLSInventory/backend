import copy
import os
import typing
from hashlib import sha256

import app
import app.db_models as db_models
import app.db_schemas as db_schemas

from loguru import logger
import app.object_models as object_models
import app.utils.sslyze.simplify_result as sslyze_result_simplify
from config import SslyzeConfig

from sqlalchemy.exc import IntegrityError
import json
import datetime

import app.utils.certificate as certificate
import app.utils.db.basic as db_utils
import app.utils.db.advanced as db_utils_advanced
import app.utils.files as files

still_to_parse_test = True


def try_to_add(obj):
    try:
        app.db.add(obj)
        app.db.commit()
    except IntegrityError as _:
        logger.error("IntegrityError on inserting object (possible duplicity): " + str(obj))
        app.db.rollback()


def basic_db_fill_test():
    logger.debug("DB Basic fill test started")

    # scan_result = ScanResult(scanTargetID=1, scanType="TEST-TYPE", duration=0, status=404, result="TEST-RESULT")
    # try_to_add(scan_result)

    logger.debug("DB Basic fill test finished")


def parse_cipher_suite(scan_result, plugin_title):
    protocol_str = plugin_title[:].replace(" Cipher Suites", "")
    print(plugin_title)

    res = app.db_models.CipherSuiteScanResult()
    res.protocol = protocol_str
    res.preferred_cipher_id = app.db_models.AcceptedCipherSuite.from_dict(scan_result["results"][plugin_title][
                                                                              "preferred_cipher"])

    plugin_fields = {
        # "preferred_cipher": {"elem_type": AcceptedCipherSuite, "expected_fields": ["openssl_name", "ssl_version", "is_anonymous", "key_size", "post_handshake_response"]},
        "accepted_cipher_list": {"elem_type": app.db_models.AcceptedCipherSuite,
                                 "expected_fields": ["openssl_name", "ssl_version", "is_anonymous", "key_size",
                                                     "post_handshake_response"]},
        "rejected_cipher_list": {"elem_type": app.db_models.RejectedCipherSuite,
                                 "expected_fields": ["openssl_name", "ssl_version", "is_anonymous",
                                                     "handshake_error_message"]},
        "errored_cipher_list": {},  # todo: errored_cipher_list
    }

    for plugin_field in plugin_fields:
        current_plugin_fields = plugin_fields[plugin_field]
        list_of_results = scan_result["results"][plugin_title][plugin_field]

        answer_list = []
        for single_cipher in list_of_results:
            assert single_cipher is not None
            if len(current_plugin_fields) == 0:
                # todo: handling of errored_cipher_list
                logger.warning(f'parse_cipher_suite: probably not implemented parsing for {plugin_field}')
                continue
            param_order = current_plugin_fields["expected_fields"]

            cipher_id = current_plugin_fields["elem_type"].from_dict(single_cipher)
            answer_list.append(cipher_id)

            if still_to_parse_test:
                for s_param in param_order:
                    single_cipher.pop(s_param, None)

        answer_string = str(answer_list)
        logger.info(f"{plugin_title}: {plugin_field}: {answer_string}")

        setattr(res, plugin_field, answer_string)

        if still_to_parse_test:
            scan_result["results"][plugin_title].pop("preferred_cipher", None)
            if scan_result["results"][plugin_title][plugin_field] is not None:
                scan_result["results"][plugin_title][plugin_field] = list(
                    filter(None, scan_result["results"][plugin_title][plugin_field]))
            if scan_result["results"][plugin_title][plugin_field] is None or len(
                    scan_result["results"][plugin_title][plugin_field]) == 0:
                scan_result["results"][plugin_title].pop(plugin_field, None)

    res, existing = db_utils.get_one_or_create_from_object(res)
    return res.id


def parse_server_info(scan_result):
    server_info_part = scan_result["server_info"]
    cipher_res_id = app.db_models.CipherSuite.id_from_parts(server_info_part["openssl_cipher_string_supported"],
                                                            server_info_part["highest_ssl_version_supported"])
    res = app.db_models.ServerInfo(hostname=server_info_part["hostname"], port=server_info_part["port"],
                                   ip_address=server_info_part["ip_address"],
                                   openssl_cipher_string_supported_id=cipher_res_id)
    res = db_utils_advanced.generic_get_create_edit_from_transient(db_schemas.ServerInfoSchema, res)

    if still_to_parse_test:
        scan_result.pop("server_info")

    return res.id


def parse_certificate_chain(obj):
    if obj is None:
        return None
    answer = []
    for i in range(len(obj)):
        cur_crt = parse_certificate(obj[i])
        answer.append(cur_crt)

    return app.db_models.CertificateChain.from_list(answer)


def parse_single_ocsp_response(obj) -> int:
    crt_obj = db_utils.dict_filter_to_class_variables(app.db_models.OCSPResponseSingle, obj)

    crt_obj["certID_hashAlgorithm"] = obj["certID"]["hashAlgorithm"]
    crt_obj["certID_issuerNameHash"] = obj["certID"]["issuerNameHash"]
    crt_obj["certID_issuerKeyHash"] = obj["certID"]["issuerKeyHash"]
    crt_obj["certID_serialNumber"] = obj["certID"]["serialNumber"]

    crt_obj["thisUpdate"] = datetime.datetime.strptime(obj["thisUpdate"], '%b %d %H:%M:%S %Y %Z')
    crt_obj["nextUpdate"] = datetime.datetime.strptime(obj["nextUpdate"], '%b %d %H:%M:%S %Y %Z')

    # crt_obj["thisUpdate"] = str(crt_obj["thisUpdate"])
    # crt_obj["nextUpdate"] = str(crt_obj["nextUpdate"])

    res = db_utils.get_or_create_or_update_by_unique(app.db_models.OCSPResponseSingle, crt_obj)
    # res = db_utils_advanced.generic_get_create_edit_from_data(db_schemas.OCSPResponseSingleSchema, crt_obj) # this doesn't work, because datetime problems

    return res.id


def parse_certificate_information_ocsp_response(obj) -> int:
    if obj is None:
        return None
    obj["responses_list"] = []
    for x in obj["responses"]:
        obj["responses_list"].append(parse_single_ocsp_response(x))

    obj["producedAt"] = datetime.datetime.strptime(obj["producedAt"], '%b %d %H:%M:%S %Y %Z')
    obj["responses_list"] = ",".join(str(x) for x in obj["responses_list"])

    crt_obj = db_utils.dict_filter_to_class_variables(app.db_models.OCSPResponse, obj)
    # res = app.db_models.OCSPResponse.from_kwargs(crt_obj)

    res = db_utils.get_or_create_or_update_by_unique(app.db_models.OCSPResponse, crt_obj)
    # res = db_utils_advanced.generic_get_create_edit_from_data(db_schemas.OCSPResponseSchema, crt_obj) # this doesn't work, because datetime problems

    if still_to_parse_test:
        obj.pop("responses")

    return res.id


def parse_certificate_information(scan_result, plugin_title):
    current_plugin = scan_result["results"][plugin_title]
    # logger.debug(current_plugin)

    current_plugin["received_certificate_chain_list_id"] = parse_certificate_chain(current_plugin[
                                                                                       "received_certificate_chain"])
    current_plugin["verified_certificate_chain_list_id"] = parse_certificate_chain(current_plugin[
                                                                                       "verified_certificate_chain"])
    current_plugin["validated_paths_list"] = []
    for validated_paths in current_plugin["path_validation_result_list"]:
        trust_store = app.db_models.TrustStore.from_dict(validated_paths["trust_store"])
        chain = parse_certificate_chain(validated_paths["verified_certificate_chain"])
        verify_string = validated_paths["verify_string"]

        current_plugin["validated_paths_list"].append(  # todo
            {"trust_store": trust_store, "chain": chain, "verify_string": verify_string})

    current_plugin["ocsp_response_id"] = parse_certificate_information_ocsp_response(current_plugin["ocsp_response"])
    tmp_validated_path_ids = []

    for validated_path in current_plugin["validated_paths_list"]:
        new_id = app.db_models.ValidatedPath.from_kwargs({"trust_store_id": validated_path["trust_store"],
                                                          "chain_id": validated_path["chain"],
                                                          "verify_string": validated_path["verify_string"],
                                                          })
        tmp_validated_path_ids.append(str(new_id))
    current_plugin["path_validation_result_list"] = ", ".join(tmp_validated_path_ids)
    current_plugin.pop("validated_paths_list")
    prep_obj = db_utils.dict_filter_to_class_variables(app.db_models.CertificateInformation, current_plugin)
    # prep_obj["path_validation_error_list"] = ",".join(prep_obj["path_validation_error_list"])

    # prep_obj.pop("ocsp_response") # todo: check
    prep_obj.pop("path_validation_error_list")
    # prep_obj.pop("path_validation_result_list") # todo

    res, existing = db_utils.get_one_or_create(app.db_models.CertificateInformation, **prep_obj)
    # res = db_utils_advanced.generic_get_create_edit_from_data(db_schemas.CertificateInformationSchema, prep_obj) # todo: general

    # logger.error([x for x in current_plugin.keys() if "certificate_chain" in x])
    if still_to_parse_test:
        current_plugin.pop("received_certificate_chain")
        current_plugin.pop("verified_certificate_chain")
        current_plugin.pop("path_validation_result_list")
        current_plugin.pop("ocsp_response")
        scan_result["results"].pop(plugin_title)

    return res.id


def parse_certificate(obj):
    try:
        crt_obj = db_utils.dict_filter_to_class_variables(app.db_models.Certificate, obj)
        crt_obj["thumbprint_sha1"] = certificate.certificate_thumbprint(crt_obj["as_pem"], "sha1")
        crt_obj["thumbprint_sha256"] = certificate.certificate_thumbprint(crt_obj["as_pem"], "sha256")

        crt_obj["publicKey_algorithm"] = obj["publicKey"]["algorithm"]
        crt_obj["publicKey_size"] = obj["publicKey"]["size"]
        crt_obj["publicKey_curve"] = obj["publicKey"].get("curve", None)
        crt_obj["publicKey_exponent"] = obj["publicKey"].get("exponent", None)

        crt_obj["notBefore"] = datetime.datetime.strptime(obj["notBefore"], '%Y-%m-%d %H:%M:%S')
        crt_obj["notAfter"] = datetime.datetime.strptime(obj["notAfter"], '%Y-%m-%d %H:%M:%S')

        crt_obj["subject_alternative_name_list"] = ",".join(obj.get("subjectAlternativeName", {}).get("DNS", []))
    except Exception as e:
        logger.exception(e)
        logger.error(obj)

    res, existing = db_utils.get_one_or_create(app.db_models.Certificate, **crt_obj)
    # res = db_utils_advanced.generic_get_create_edit_from_data(db_schemas.CertificateSchema, crt_obj)  # todo: general
    return res.id


def parse_http_security_headers(scan_result, plugin_title):
    current_plugin = scan_result["results"][plugin_title]
    current_plugin["verified_certificate_chain_list_id"] = parse_certificate_chain(current_plugin[
                                                                                       "verified_certificate_chain"])
    prep_obj = db_utils.dict_filter_to_class_variables(app.db_models.Certificate, current_plugin)
    if current_plugin["expect_ct_header"]:
        prep_obj["expect_ct_header_max_age"] = current_plugin["expect_ct_header"]["max_age"]
        prep_obj["expect_ct_header_report_uri"] = current_plugin["expect_ct_header"]["report_uri"]
        prep_obj["expect_ct_header_enforce"] = current_plugin["expect_ct_header"]["enforce"]

    # res = db_utils.get_one_or_create(app.db_models.HTTPSecurityHeaders, **prep_obj)
    res = db_utils_advanced.generic_get_create_edit_from_data(db_schemas.HTTPSecurityHeadersSchema, prep_obj)

    if still_to_parse_test:
        current_plugin.pop("verified_certificate_chain")
        scan_result["results"].pop(plugin_title)

    return res.id


def parse_tls12_session_resumption(class_type, scan_result, plugin_title):
    current_plugin = scan_result["results"][plugin_title]
    current_plugin["errored_resumptions_list"] = ",".join(current_plugin["errored_resumptions_list"])
    kwargs = db_utils.dict_filter_to_class_variables(class_type, current_plugin)
    res = class_type.from_kwargs(kwargs)    # todo: use general util
    if still_to_parse_test:
        scan_result["results"].pop(plugin_title)
    return res


def parse_general(class_type, scan_result, plugin_title):
    current_plugin = scan_result["results"][plugin_title]
    res = class_type.from_kwargs(current_plugin)  # todo: use general util
    if still_to_parse_test:
        scan_result["results"].pop(plugin_title)
    return res


@logger.catch
def run():
    # basic_db_fill_test(session)
    scan_result_string = files.read_from_file("../../tmp/test_copy.out.json")  # todo: fix path
    scan_result = json.loads(scan_result_string)
    insert_scan_result_into_db(scan_result)


def calculate_and_insert_scan_result_simplified_into_db(scan_result: db_models.ScanResults):
    scan_result_simple = sslyze_result_simplify.sslyze_result_simplify(scan_result)
    return db_utils_advanced.generic_get_create_edit_from_transient(
        db_schemas.ScanResultsSimplifiedSchema,
        scan_result_simple
    )


def insert_scan_result_into_db(scan_result_orig: dict) -> app.db_models.ScanResults:
    obj = app.db_models.ScanResults()

    scan_result = copy.deepcopy(scan_result_orig)

    target_dict = scan_result.get("target", {})
    target = object_models.TargetWithExtra.transient_from_dict(target_dict)

    if SslyzeConfig.save_results_also_to_tmp_files:
        scan_result_string = json.dumps(scan_result, indent=3)
        hash_res = sha256(scan_result_string.encode("utf8")).hexdigest()
        name = f'{target.target_definition.hostname}-{hash_res}.json'

        if not os.path.isfile(name):
            files.create_folder_if_doesnt_exist('tmp/scan_result')
            files.write_to_file(f'tmp/scan_result/{name}', scan_result_string)
            del scan_result_string
            del hash_res
            del name

    general_parser_matching = {
        "Deflate Compression": app.db_models.DeflateCompression,
        "Session Renegotiation": app.db_models.SessionRenegotiation,
        "TLS 1.3 Early Data": app.db_models.TLS13EarlyData,
        "OpenSSL CCS Injection": app.db_models.OpenSSLCCSInjection,
        "OpenSSL Heartbleed": app.db_models.OpenSSLHeartbleed,
        "Downgrade Attacks": app.db_models.DowngradeAttack,
        "ROBOT Attack": app.db_models.ROBOTAttack,
        "TLS 1.2 Session Resumption Rate": app.db_models.TLS12SessionResumptionRate,
    }

    for plugin_title in scan_result["results"]:
        if " Cipher Suites" in plugin_title:
            new_title = plugin_title[:] \
                .replace(" Cipher Suites", "") \
                .replace(".", "") \
                .replace(" ", "") \
                .replace("_", "") \
                .lower()
            new_title += "_id"
            x = parse_cipher_suite(scan_result, plugin_title)
            setattr(obj, new_title, x)

    if scan_result["results"].get("Certificate Information", None):
        # this expects Ciphers Suites to be parsed
        obj.certificate_information_id = parse_certificate_information(scan_result, "Certificate Information")

    if scan_result["results"].get("HTTP Security Headers", None):
        # this expects Ciphers Suites to be parsed
        obj.http_security_headers_id = -1
        try:
            obj.http_security_headers_id = parse_http_security_headers(scan_result, "HTTP Security Headers")
        except Exception as e:
            logger.exception(e)

    if scan_result["results"].get("TLS 1.2 Session Resumption Support", None):
        # this expects Ciphers Suites to be parsed
        obj.tls_12_session_resumption_support_id = parse_tls12_session_resumption(
            app.db_models.TLS12SessionResumptionSupport,
            scan_result,
            "TLS 1.2 Session Resumption Support")

    if scan_result["results"].get("TLS 1.2 Session Resumption Rate", None):
        # this expects Ciphers Suites to be parsed
        obj.tls_12_session_resumption_rate_id = parse_tls12_session_resumption(app.db_models.TLS12SessionResumptionRate,
                                                                               scan_result,
                                                                               "TLS 1.2 Session Resumption Rate")

    for plugin_title in general_parser_matching:
        if scan_result["results"].get(plugin_title, None):
            x = parse_general(general_parser_matching[plugin_title], scan_result, plugin_title)
            new_title = plugin_title.lower().replace(".", "").replace(" ", "_")
            new_title += "_id"
            setattr(obj, new_title, x)

    if scan_result.get("server_info", None):
        # this expects Ciphers Suites to be parsed
        obj.server_info_id = parse_server_info(scan_result)

    res: typing.Optional[db_models.ScanResults] = \
        db_utils_advanced.generic_get_create_edit_from_transient(db_schemas.ScanResultsForeignKeysOnlySchema, obj)  # todo: general

    if res is None:
        logger.warning("Error inserting Scan result to DB. Aborting.")
        return

    scanresult_id = res.id
    update_references_to_scan_result(target, scanresult_id)

    calculate_and_insert_scan_result_simplified_into_db(res)

    if still_to_parse_test:
        to_remove = []
        for plugin_title in scan_result["results"]:
            if not scan_result["results"][plugin_title]:
                to_remove.append(plugin_title)
        for plugin_title in to_remove:
            scan_result["results"].pop(plugin_title, None)
        # files.write_to_file("../../tmp/still_to_parse.out.json", json.dumps(scan_result, indent=3))  # todo: fix path

    return obj


def update_references_to_scan_result(twe: object_models.TargetWithExtra, scanresult_id: int):
    target = twe.target_definition
    target_with_ip = db_utils_advanced.generic_get_create_edit_from_transient(db_schemas.TargetSchema,
                                                                              target,
                                                                              get_only=True)
    if target_with_ip is not None:
        update_references_to_scan_result_single_target(target_with_ip.id, scanresult_id)

    if twe.extra.get("comes_from_dns"):
        target_copy = db_utils_advanced.generic_get_create_edit_from_transient(db_schemas.TargetSchema,
                                                                               target,
                                                                               transient_only=True)
        target_copy.ip_address = None
        target_without_ip = db_utils_advanced.generic_get_create_edit_from_transient(db_schemas.TargetSchema,
                                                                                     target,
                                                                                     get_only=True)
        if target_without_ip is not None:
            update_references_to_scan_result_single_target(target_without_ip.id, scanresult_id)


def update_references_to_scan_result_single_target(target_id: int, scanresult_id: int):
    db_utils_advanced.generic_get_create_edit_from_data(db_schemas.ScanResultsHistorySchema,
                                                        {'target_id': target_id,
                                                         'scanresult_id': scanresult_id,
                                                         'timestamp': db_models.datetime_to_timestamp(
                                                             datetime.datetime.now())
                                                         })

    # ls = db_utils_advanced.generic_get_create_edit_from_data(db_schemas.LastScanSchema,
    #                                                          {'target_id': target_id,
    #                                                           'last_scanned': db_models.datetime_to_timestamp(datetime.datetime.now()),
    #                                                           'scanresult_id': scanresult_id,
    #                                                           # 'last_enqueued': # previous value
    #                                                           })

    ls = db_utils_advanced.generic_get_create_edit_from_data(db_schemas.LastScanSchema,
                                                             {'target_id': target_id},
                                                             get_only=True)
    if ls is None:
        logger.error(f"Scan result for a target which doesn't have Last Scan record. {target_id}")
        return
    ls.last_scanned = db_models.datetime_to_timestamp(datetime.datetime.now())
    ls.result_id = scanresult_id
    db_utils_advanced.generic_get_create_edit_from_transient(db_schemas.LastScanSchema, ls)

import datetime
import json
from typing import Optional, List, Dict, Tuple
from itertools import chain

import app.scan_scheduler as scan_scheduler
from app import db_models, db_schemas, logger
import app.object_models as object_models
import app.utils.sslyze.scanner as sslyze_scanner
import app.utils.db.basic as db_utils
from app.utils.time_helper import time_source, datetime_to_timestamp

from . import sensor_collector

from config import SensorCollector


def get_target_definition_by_ids(target_ids: List[int], user_id: int) -> bool:
    res = db_models.db.session.query(db_models.ScanOrder) \
        .filter(db_models.ScanOrder.user_id == user_id)\
        .filter(db_models.ScanOrder.target_id.in_(target_ids))\
        .all()
    return res


def can_user_get_target_definition_by_id(target_id: int, user_id: int) -> bool:
    return get_target_definition_by_ids([target_id], user_id) is not None


def full_target_settings_to_dict(target: db_models.Target, scan_order: db_models.ScanOrder,
                                 notifications: dict) -> dict:
    return {
        "target": db_schemas.TargetSchema().dump(target),
        "scanOrder": db_schemas.ScanOrderSchema(only=("periodicity", "active")).dump(scan_order),
        "notifications": notifications
    }


def get_target_from_id(target_id: int) -> db_models.Target:
    return db_models.db.session.query(db_models.Target).get(target_id)


def get_target_from_id_if_user_can_see(target_id: int, user_id: int) -> Optional[db_models.Target]:
    # validate that the user entered the target definition at least once. Protection against enumaration attack.
    if not can_user_get_target_definition_by_id(target_id, user_id):
        return None

    # The following should always pass. If there isn't target, there shouldn't be scan order.
    return get_target_from_id(target_id)


def sslyze_scan(twe: List[object_models.TargetWithExtra], save_result=True) -> Dict:
    if SensorCollector.PUT_WORK_TO_REDIS_JOB_QUEUE:
        ntwe_json_list = object_models.TargetWithExtraSchema().dump(twe, many=True)
        ntwe_json_string = json.dumps(ntwe_json_list)

        import app.utils.sslyze.background_redis as sslyze_background_redis
        return {'results_attached': False,
                'backgroud_job_id': sslyze_background_redis.redis_sslyze_enqueu(ntwe_json_string)}

    list_of_results_as_json = sslyze_scanner.scan_domains_to_arr_of_dicts(twe)
    answer = {'results_attached': True, 'results': list_of_results_as_json}
    if save_result:
        sensor_collector.sslyze_save_scan_results(answer)
    return answer


def sslyze_enqueue_waiting_scans_multiple_batches(n_batches):
    # todo: this has different interface from sslyze_enqueue_waiting_scans_single_batch. Unify it.
    for i in range(n_batches):
        sslyze_enqueue_waiting_scans_single_batch()
    return f' {n_batches} batches enqueued or scanned'


def sslyze_enqueue_waiting_scans_single_batch():
    if SensorCollector.GET_WORK_OVER_HTTP:
        # todo: get from collector
        logger.error("SL0001 sslyze_enqueue_waiting_scans called with SensorCollector.GET_WORK_OVER_HTTP enabled. This is currently not implemented.")
        return  # todo: return

    twe = scan_scheduler.get_batch_to_scan()
    if len(twe) == 0:
        return {'results_attached': False,
                'empty_job': True}

    return sslyze_scan(twe)


def get_last_scan_and_result(target_id: int, user_id: int) -> Optional[
        Tuple[db_models.LastScan, db_models.ScanResults]]:
    if not can_user_get_target_definition_by_id(target_id, user_id):
        return None

    scan_result = db_models.db.session \
        .query(db_models.LastScan, db_models.ScanResults) \
        .filter(db_models.LastScan.target_id == target_id) \
        .filter(db_models.LastScan.result_id == db_models.ScanResults.id) \
        .first()

    return scan_result


def get_scan_history(user_id: int, x_days: int = 30):  # -> Optional[Tuple[db_models.LastScan, db_models.ScanResults]]:
    today = time_source.time()
    start = today - datetime.timedelta(days=x_days)
    start_timestamp = datetime_to_timestamp(start)

    res = db_models.db.session \
        .query(db_models.ScanOrder, db_models.Target, db_models.ScanResultsHistory, db_models.ScanResultsSimplified, db_models.ServerInfo) \
        .outerjoin(db_models.ScanResultsHistory,
                   db_models.ScanResultsHistory.target_id == db_models.ScanOrder.target_id) \
        .outerjoin(db_models.ScanResultsSimplified,
                   db_models.ScanResultsHistory.scanresult_id == db_models.ScanResultsSimplified.scanresult_id) \
        .outerjoin(db_models.ScanResults,
                   db_models.ScanResultsHistory.scanresult_id == db_models.ScanResults.id) \
        .outerjoin(db_models.ServerInfo,
                   db_models.ScanResults.server_info_id == db_models.ServerInfo.id) \
        .filter(db_models.ScanOrder.target_id == db_models.Target.id) \
        .filter(db_models.ScanOrder.active == True) \
        .filter(db_models.ScanOrder.user_id == user_id) \
        .filter(db_models.ScanResultsHistory.timestamp >= start_timestamp) \
        .all()

    return res


def get_certificate_chains(user_id: int, x_days: int = 30) -> List[db_models.CertificateChain]:
    res: List[db_models.ScanResultsHistory] = get_scan_history(user_id, x_days)

    ans1a = map(lambda x: x.ScanResultsSimplified if x else None, res)
    ans1b = filter(lambda x: x, ans1a)
    asn1c = list(ans1b)  # This is necessary, because we're going to need to iterate twice over the array.

    ans2a = map(lambda x: x.verified_certificate_chains_lists_ids if x.verified_certificate_chains_lists_ids else None, asn1c)
    ans2b = map(lambda x: str(x.received_certificate_chain_list_id) if x.received_certificate_chain_list_id else None, asn1c)
    ans2c = chain(ans2a, ans2b)

    ans2d = list(ans2c)

    return db_utils.arr_of_stringarrs_to_arr_of_objects(
        ans2d,
        db_models.CertificateChain
    )


def get_certificates(chains: List[db_models.CertificateChain]) -> List[db_models.Certificate]:
    ans1a = map(lambda x: x.chain if x else None, chains)

    return db_utils.arr_of_stringarrs_to_arr_of_objects(
        list(ans1a),
        db_models.Certificate
    )

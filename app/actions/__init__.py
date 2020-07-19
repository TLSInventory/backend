import datetime
import json
from typing import Optional, List, Dict, Tuple

import app.scan_scheduler as scan_scheduler
from app import db_models, db_schemas, logger
import app.object_models as object_models
import app.utils.sslyze.scanner as sslyze_scanner
import app.utils.sslyze.parse_result as sslyze_parse_result

from . import sensor_collector

from config import FlaskConfig, SslyzeConfig, SensorCollector


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


def sslyze_enqueue_waiting_scans():
    if SensorCollector.GET_WORK_OVER_HTTP:
        # todo: get from collector
        logger.error("sslyze_enqueue_waiting_scans called with SensorCollector.GET_WORK_OVER_HTTP enabled. This is currently not implemented.")
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
        .one()

    return scan_result


def get_scan_history(user_id: int, x_days: int = 30):  # -> Optional[Tuple[db_models.LastScan, db_models.ScanResults]]:
    today = datetime.datetime.now()
    start = today - datetime.timedelta(days=x_days)
    start_timestamp = db_models.datetime_to_timestamp(start)

    res = db_models.db.session \
        .query(db_models.ScanOrder, db_models.Target, db_models.ScanResultsHistory, db_models.ScanResultsSimplified) \
        .outerjoin(db_models.ScanResultsHistory,
                   db_models.ScanResultsHistory.target_id == db_models.ScanOrder.target_id) \
        .outerjoin(db_models.ScanResultsSimplified,
                   db_models.ScanResultsHistory.scanresult_id == db_models.ScanResultsSimplified.scanresult_id) \
        .filter(db_models.ScanOrder.target_id == db_models.Target.id) \
        .filter(db_models.ScanOrder.active == True) \
        .filter(db_models.ScanOrder.user_id == user_id) \
        .filter(db_models.ScanResultsHistory.timestamp >= start_timestamp) \
        .all()

    return res

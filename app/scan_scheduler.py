import datetime
import itertools
from typing import Optional, List
from sqlalchemy import func
from loguru import logger

import app
import app.db_models as db_models
from config import SchedulerConfig
import app.utils.db.basic as db_utils
import app.utils.dns_utils as dns_utils
import app.object_models as object_models

db = app.db


def default_current_time(query_compare_time=None):
    if query_compare_time is None:
        query_compare_time = datetime.datetime.now()
    return query_compare_time


def offset_time_back_from_now(n_secs):
    return datetime.datetime.now() - datetime.timedelta(seconds=n_secs)


def default_enqueued_offseted_timestamp():
    offseted_datetime = offset_time_back_from_now(SchedulerConfig.enqueue_min_time)
    return db_models.datetime_to_timestamp(offseted_datetime)


def update_scan_order_minimal_for_target(target_id: int) -> Optional[int]:
    logger.info(f"Updating minimal scan order for target_id: {target_id}")
    res = db.session.query(func.min(db_models.ScanOrder.periodicity)) \
        .filter(db_models.ScanOrder.target_id == target_id) \
        .filter(db_models.ScanOrder.active == True) \
        .one()
    min_periodicity = res[0]

    if min_periodicity is None:
        db_models.ScanOrderMinimal.query.filter_by(id=target_id).delete()
        db.session.commit()
        return min_periodicity

    som, _ = db_utils.get_one_or_create(db_models.ScanOrderMinimal, **{"id": target_id})
    if som.periodicity != min_periodicity:
        som.periodicity = min_periodicity
        db.session.commit()

    return min_periodicity


def qry_scan_base():
    date_offseted = default_enqueued_offseted_timestamp()
    return db.session.query(db_models.ScanOrderMinimal.id) \
        .filter(db_models.LastScan.id == db_models.ScanOrderMinimal.id) \
        .filter((db_models.LastScan.last_enqueued < date_offseted) |
                (db_models.LastScan.last_enqueued.is_(None)))


def qry_first_scan():
    return qry_scan_base() \
        .filter(db_models.LastScan.last_scanned.is_(None))


def qry_rescan(query_compare_time=None):
    query_compare_time = db_models.datetime_to_timestamp(default_current_time(query_compare_time))
    return qry_scan_base() \
        .filter(db_models.LastScan.last_scanned + db_models.ScanOrderMinimal.periodicity < query_compare_time) \
        .order_by((db_models.LastScan.last_enqueued).desc()) # todo: check the sum is working


def get_backlog_count_first_scan():
    return qry_first_scan().count()


def get_backlog_count_first_scan():
    return qry_rescan().count()


def get_due_targets(limit_n=SchedulerConfig.batch_increments):
    res_first_scan = qry_first_scan().limit(limit_n).all()
    remains_empty_in_batch = limit_n - len(res_first_scan)

    res_rescan = []
    if remains_empty_in_batch > 0:
        res_rescan = qry_rescan().limit(remains_empty_in_batch).all()

    logger.debug(f"Get due targets (first scan) of {len(res_first_scan)} elements with limit {limit_n}: {res_first_scan}")
    logger.debug(f"Get due targets (rescan) of {len(res_rescan)} elements with limit {remains_empty_in_batch}: {res_rescan}")

    return [x[0] for x in (res_first_scan + res_rescan)]


def mark_enqueued_targets(target_ids, time=None):
    if not target_ids:
        return
    if time is None:
        time = db_models.datetime_to_timestamp(default_current_time(time))
    db.session.query(db_models.LastScan)\
        .filter(db_models.LastScan.id.in_(tuple(target_ids)))\
        .update({db_models.LastScan.last_enqueued: time}, synchronize_session='fetch')
    db.session.commit()


def mark_scanned_targets(target_ids: List[int], time=None):
    if not target_ids:
        return
    if time is None:
        time = db_models.datetime_to_timestamp(default_current_time(time))
    db.session.query(db_models.LastScan)\
        .filter(db_models.LastScan.id.in_(tuple(target_ids)))\
        .update({db_models.LastScan.last_scanned: time}, synchronize_session='fetch')
    db.session.commit()


def backdate_enqueued_targets():
    query_compare_time = db_models.datetime_to_timestamp(default_enqueued_offseted_timestamp())
    res = db.session.query(db_models.LastScan.id) \
        .filter(db_models.ScanOrderMinimal.id == db_models.LastScan.id) \
        .filter(db_models.LastScan.last_enqueued > query_compare_time) \
        .limit(SchedulerConfig.batch_size) \
        .all()

    new_ids = [x[0] for x in res]
    mark_enqueued_targets(new_ids, default_enqueued_offseted_timestamp())
    return len(new_ids)


def convert_batch_to_scan_to_list_of_dicts(twe: List[object_models.TargetWithExtra]=None) -> List[dict]:
    if twe is None:
        twe = []
    return [x.json_repr() for x in twe]


def get_batch_to_scan(limit_n=SchedulerConfig.batch_size) -> List[object_models.TargetWithExtra]:
    targets_e = set()
    while len(targets_e) < limit_n:
        original_size = len(targets_e)

        remaining_slots = limit_n - len(targets_e)
        next_due_targets_request_size = min(SchedulerConfig.batch_increments, remaining_slots)

        new_ids = get_due_targets(next_due_targets_request_size)
        mark_enqueued_targets(new_ids)

        new_targets = db.session.query(db_models.Target) \
            .filter(db_models.Target.id.in_(tuple(new_ids))) \
            .all()

        for single_target in new_targets:
            single_target: db_models.Target
            if single_target.ip_address:
                new_target_with_extra = object_models.TargetWithExtra(single_target, {"comes_from_dns": False})
                targets_e.add(new_target_with_extra)
                continue

            ips = dns_utils.get_ips_for_domain(single_target.hostname)

            if len(ips) == 0:
                mark_scanned_targets([single_target.id])
                logger.info(f'No DNS results for {single_target.hostname} (id {single_target.id}).')
                # todo: produce result with information about empty reason for scan failure
                continue

            for ip in ips:
                new_target = single_target.make_copy()
                ip_type, ip_addr = ip
                new_target.ip_address = ip_addr
                new_target_with_extra = object_models.TargetWithExtra(new_target, {"comes_from_dns": True})
                targets_e.add(new_target_with_extra)

        new_size = len(targets_e)

        if original_size == new_size:
            break  # there are apparently no new targets

    return deduplicate_scan_orders(targets_e)


def deduplicate_scan_orders(targets_e: List[object_models.TargetWithExtra]):
    unique_targets_repr = set()
    unique_targets = []

    targets_from_dns = filter(lambda x: x.extra.get("comes_from_dns", False), targets_e)
    targets_direct_ip = filter(lambda x: not x.extra.get("comes_from_dns", False), targets_e)

    # In case of when bot target that has IP from DNS and target that has static IP, prefer the one from DNS.
    # If comes_from_dns is present in scan result, then the both direct IP and DNS version get the scan result.

    for x in itertools.chain(targets_from_dns, targets_direct_ip):
        if repr(x.target_definition) not in unique_targets_repr:
            unique_targets_repr.add(repr(x.target_definition))
            unique_targets.append(x)
        else:
            logger.warning(f'{repr(x.target_definition)} got enqueued twice for the same scan batch.')

    targets_e = unique_targets
    logger.info(f"Batch (size {len(targets_e)} with soft max {SchedulerConfig.batch_size}): {targets_e}")

    return targets_e

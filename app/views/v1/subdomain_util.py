from typing import Set, Tuple

import json

import flask_jwt_extended
from flask import request, url_for

import app.utils.authentication_utils as authentication_utils
import app.actions as actions
import app.db_models as db_models

from . import bp
from app.utils.ct_search import get_subdomains_from_ct
from app.actions.add_targets import add_targets

from app.utils.time_helper import time_source

import config

from loguru import logger


@bp.route("/rescan_subdomains", methods=["GET"])  # is ok?
@bp.route('/rescan_subdomains/<string:sensor_key>', methods=['GET'])
def api_cron_rescan_subdomains(sensor_key: str) -> None:
    # currently using sensor key - should be ok, ask Ondra
    # maybe good idea to pull local auth somewhere else
    valid_access = False
    if config.SensorCollector.KEY and sensor_key:
        valid_access = config.SensorCollector.KEY == sensor_key
    if config.SensorCollector.KEY_SKIP_FOR_LOCALHOST and request.remote_addr == '127.0.0.1':
        valid_access = True
    if not valid_access:
        logger.warning(
            f'DN0006 Request to rescan subdomains: unauthorized: key: {sensor_key}, IP: {request.remote_addr}')
        return
    rescan_subdomains()


def rescan_subdomains() -> int:
    current_time = time_source.timestamp()
    targets_to_rescan = (
        db_models.db.session.query(db_models.SubdomainRescanTarget)
        .filter(
            current_time - db_models.SubdomainRescanTarget.subdomain_last_scan <
            config.SubdomainRescanConfig.SUBDOMAIN_RESCAN_INTERVAL
        )
        .order_by(db_models.SubdomainRescanTarget.subdomain_last_scan.asc())
        .limit(config.SubdomainRescanConfig.SUBDOMAIN_BATCH_SIZE).all()
    )
    for target in targets_to_rescan:
        add_subdomains(target.subdomain_scan_target_id, target.subdomain_scan_user_id)
        target.subdomain_last_scan = time_source.timestamp()
        db_models.db.session.commit()
    return len(targets_to_rescan)  # for testing


def add_subdomains(target_id: int, user_id: int, data) -> Tuple[str, int, int]:
    target = actions.get_target_from_id_if_user_can_see(target_id, user_id)

    if target is None:
        return "You do not have permission to track this target.", 0, 400

    if data is None:  # dummy data for searching and enqueuing new subdomains
        data = get_dummy_target_data(target.hostname)

    existing_subdomain_rescan_target = db_models.db.session. \
        query(db_models.SubdomainRescanTarget). \
        filter(db_models.SubdomainRescanTarget.subdomain_scan_target_id == target_id). \
        filter(db_models.SubdomainRescanTarget.subdomain_scan_user_id == user_id). \
        all()

    if not existing_subdomain_rescan_target:
        new = db_models.SubdomainRescanTarget()

        new.subdomain_scan_target_id = target_id
        new.subdomain_scan_user_id = user_id
        new.subdomain_last_scan = time_source.timestamp()

        db_models.db.session.add(new)
        db_models.db.session.commit()

    subdomains = subdomain_lookup(target, user_id)
    subdomain_ids = add_targets(list(subdomains), user_id, data)

    return f"Successfully added {len(subdomain_ids)} subdomains", len(subdomain_ids), 200


@bp.route("/api_add_subdomains/<int:target_id>", methods=["POST", "DELETE"])
@flask_jwt_extended.jwt_required
def api_add_subdomains(target_id: int):
    user_id = authentication_utils.get_user_id_from_current_jwt()
    data = json.loads(request.data)

    return add_subdomains(target_id, user_id, data)


def get_tracked_subdomains_by_hostname(
    hostname: str, user_id: int
) -> Set[str]:
    # assumes there is a relationship between Target and ScanOrder
    db_response = (
        db_models.db.session.query(db_models.Target)
        .outerjoin(db_models.ScanOrder)
        .filter(db_models.ScanOrder.user_id == user_id)
        .filter(db_models.Target.hostname.like(f"%{hostname}"))
        .all()
    )

    return set(map(lambda target: target.hostname, db_response))


def subdomain_lookup(target: db_models.Target, user_id: int) -> Set[str]:
    tracked_subdomains = get_tracked_subdomains_by_hostname(target.hostname, user_id)
    all_subdomains = set(get_subdomains_from_ct(target.hostname))
    return all_subdomains - tracked_subdomains


def get_dummy_target_data(hostname: str):
    dummy_data = {
        "scanOrder": {"active": None, "periodicity": 43200},
        "target": {
            "hostname": f"{hostname}",
            "id": None,
            "ip_address": None,
            "port": None,
            "protocol": "HTTPS",
        },
    }
    return dummy_data

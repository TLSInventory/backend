import datetime
import json
from typing import List

import jsons
from sqlalchemy.orm.exc import NoResultFound

import app.object_models as object_models
import app.utils.notifications.general as notifications_general
from config import SensorCollector, NotificationsConfig, SslyzeConfig

from . import bp

from flask import request, jsonify
from loguru import logger

import flask_jwt_extended

import app.scan_scheduler as scan_scheduler
import app.db_models as db_models
import app.actions as actions
import app.actions.sensor_collector as sensor_collector


@bp.route('/get_next_targets_batch')
def api_get_next_targets_batch():
    return jsonify(scan_scheduler.convert_batch_to_scan_to_list_of_dicts(scan_scheduler.get_batch_to_scan()))


@bp.route('/sslyze_scan_due_targets', methods=['GET'])
@bp.route('/sslyze_scan_due_targets/<string:sensor_key>', methods=['GET'])
def api_sslyze_scan_due_targets_via_sensor_key(sensor_key=None):
    valid_access = False
    if SensorCollector.KEY and sensor_key:
        valid_access = SensorCollector.KEY == sensor_key
    if SensorCollector.KEY_SKIP_FOR_LOCALHOST and request.remote_addr == '127.0.0.1':
        valid_access = True
    if not valid_access:
        logger.warning(
            f'Request to scan due targets: unauthorized: key: {sensor_key}, IP: {request.remote_addr}')
        return 'Access only allowed with valid SENSOR_COLLECTOR_KEY or from localhost', 401

    return actions.sslyze_enqueue_waiting_scans_single_batch()


@bp.route('/sslyze_scan_due_targets_multiple_batches', methods=['GET'])
@bp.route('/sslyze_scan_due_targets_multiple_batches/<string:sensor_key>', methods=['GET'])
def api_sslyze_scan_due_targets_multiple_batches_via_sensor_key(sensor_key=None):
    valid_access = False
    if SensorCollector.KEY and sensor_key:
        valid_access = SensorCollector.KEY == sensor_key
    if SensorCollector.KEY_SKIP_FOR_LOCALHOST and request.remote_addr == '127.0.0.1':
        valid_access = True
    if not valid_access:
        logger.warning(
            f'Request to scan due targets: unauthorized: key: {sensor_key}, IP: {request.remote_addr}')
        return 'Access only allowed with valid SENSOR_COLLECTOR_KEY or from localhost', 401

    return actions.sslyze_enqueue_waiting_scans_multiple_batches(
        SslyzeConfig.number_of_batches_per_request_for_multiple_batches)


@bp.route('/sslyze_enqueue_now/<int:target_id>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_sslyze_enqueue_now(target_id):
    try:
        res = db_models.db.session \
            .query(db_models.LastScan) \
            .filter(db_models.LastScan.target_id == target_id) \
            .one()
    except NoResultFound as e:
        return "Target id not found", 400  # todo: check status code

    res: db_models.LastScan
    res.last_scanned = None
    # todo: consider also resetting last_enqueued
    db_models.db.session.commit()
    return "ok", 200


@bp.route('/sslyze_import_scan_results', methods=['POST'])
@bp.route('/sslyze_import_scan_results/<string:sensor_key>', methods=['POST'])
def api_sslyze_import_scan_results(sensor_key=None):
    valid_access = False
    if SensorCollector.KEY and sensor_key:
        valid_access = SensorCollector.KEY == sensor_key
    if SensorCollector.KEY_SKIP_FOR_LOCALHOST and request.remote_addr == '127.0.0.1':
        valid_access = True
    if not valid_access:
        logger.warning(
            f'Request to import scan results: unauthorized: key: {sensor_key}, IP: {request.remote_addr}')
        return 'Access only allowed with valid SENSOR_COLLECTOR_KEY or from localhost', 401

    data = jsons.load(request.json, object_models.ScanResultResponse)
    if not data.results_attached:
        return "No results attached flag", 400
    sensor_collector.sslyze_save_scan_results_from_obj(data, comes_from_http=True)
    return "ok", 200


@bp.route('/notifications/send_for_period/<string:sensor_key>', methods=['GET'])
def api_send_notifications_for_period(sensor_key=None):
    valid_access = False
    if SensorCollector.KEY and sensor_key:
        valid_access = SensorCollector.KEY == sensor_key
    if SensorCollector.KEY_SKIP_FOR_LOCALHOST and request.remote_addr == '127.0.0.1':
        valid_access = True
    if not valid_access:
        logger.warning(
            f'Request to send notifications: unauthorized: key: {sensor_key}, IP: {request.remote_addr}')
        return 'Access only allowed with valid SENSOR_COLLECTOR_KEY or from localhost', 401

    timestamp_start_from = db_models.datetime_to_timestamp(
        datetime.datetime.now() -
        datetime.timedelta(minutes=NotificationsConfig.how_long_to_retry_sending_notifications)
    )

    res = db_models.db.session \
        .query(db_models.LastScan) \
        .filter(db_models.LastScan.last_scanned > timestamp_start_from) \
        .all()

    res_target_ids = sorted(set([x.target_id for x in res]))
    # res_target_ids = res_target_ids[:1000]

    count_succesfully_sent_notifications = notifications_general.schedule_notifications(res_target_ids)
    return f'{count_succesfully_sent_notifications} notifications succesfully sent'

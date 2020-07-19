from typing import List, Optional, Tuple, Dict

import app.utils.notifications.send as notifications_send
import app.db_models as db_models

from loguru import logger

import app.utils.db.basic as db_utils
from app.utils.notifications.user_preferences import get_effective_active_notification_settings
from app.utils.notifications.connection_types import Notification
from app.utils.notifications.event_type_expiration import NotificationTypeExpiration

# def get_res_old_and_new(changed_targets):
#     # todo: this might not work, it's not finished.
#     res_new = db_models.db.session \
#         .query(db_models.ScanOrder, db_models.Target, db_models.LastScan, db_models.ScanResults) \
#         .outerjoin(db_models.ScanResults, db_models.LastScan.result_id == db_models.ScanResults.id) \
#         .filter(db_models.LastScan.target_id == db_models.Target.id) \
#         .filter(db_models.ScanOrder.target_id == db_models.Target.id) \
#         .filter(db_models.ScanOrder.active == True) \
#         .filter(db_models.ScanOrder.target_id.in_(changed_targets)) \
#         .all()
#
#     minimum_wait_time = db_models.datetime_to_timestamp(datetime.datetime.now() - datetime.timedelta(minutes=5))
#
#     res_old = db_models.db.session \
#         .query(db_models.ScanOrder, db_models.Target, db_models.ScanResults) \
#         .join(db_models.ScanResultsHistory) \
#         .outerjoin(db_models.ScanResults, db_models.LastScan.result_id == db_models.ScanResults.id) \
#         .filter(db_models.ScanResultsHistory.timestamp < minimum_wait_time) \
#         .filter(db_models.ScanResultsHistory.target_id == db_models.Target.id) \
#         .filter(db_models.LastScan.target_id == db_models.Target.id) \
#         .filter(db_models.ScanOrder.target_id == db_models.Target.id) \
#         .filter(db_models.ScanOrder.active == True) \
#         .filter(db_models.ScanOrder.target_id.in_(changed_targets)) \
#         .all()
#
#     return res_old, res_new


def get_scan_data_for_notifications_scheduler(limit_to_following_target_ids: Optional[List[int]] = None):
    qry = db_models.db.session \
        .query(db_models.ScanOrder,
               db_models.Target,
               db_models.LastScan,
               db_models.ScanResults) \
        .filter(db_models.ScanOrder.active == True) \
        .filter(db_models.ScanOrder.target_id == db_models.Target.id) \
        .filter(db_models.LastScan.target_id == db_models.Target.id) \
        .filter(db_models.LastScan.result_id == db_models.ScanResults.id)

    if limit_to_following_target_ids:
        deduplicated_target_ids = list(set(limit_to_following_target_ids))
        qry = qry.filter(db_models.Target.id.in_(deduplicated_target_ids))

    res_all_active = qry.all()
    return res_all_active


def schedule_notifications(limit_to_following_target_ids: Optional[List[int]] = None):
    # Param limit_to_following_targets is used when we want to imediately send notifications on completed scan.

    main_data: Tuple[db_models.ScanOrder, db_models.Target, db_models.LastScan, db_models.ScanResults]\
        = get_scan_data_for_notifications_scheduler(limit_to_following_target_ids)
    notification_preferences_by_scan_order_id: Dict[str, dict] = make_dict_notification_settings_by_scan_order_id(main_data)
    # users_with_active_scan_orders = set([res.ScanOrder.user_id for res in main_data])

    all_new_notifications = []

    all_new_notifications.extend(
        NotificationTypeExpiration.check_condition_and_create_notifications(main_data,
                                                                            notification_preferences_by_scan_order_id))

    return send_notifications(all_new_notifications)


def make_dict_notification_settings_by_scan_order_id(main_data):
    notification_settings_by_scan_order_id = {}

    for single_res in main_data:
        scan_order_id = single_res.ScanOrder.id
        user_id = single_res.ScanOrder.user_id
        target_id = single_res.ScanOrder.target_id

        notification_settings_by_scan_order_id[scan_order_id] = get_effective_active_notification_settings(user_id, target_id)

    return notification_settings_by_scan_order_id


def send_notifications(planned_notifications: Optional[List[Notification]] = None):
    if planned_notifications is None:
        planned_notifications = []
    for x in planned_notifications:
        log_dict = {
            "sent_notification_id": x.notification_id(),
            "channel": x.channel.value
        }
        res, existing = db_utils.get_or_create_by_unique(db_models.SentNotificationsLog, log_dict, get_only=True)
        if res is None:
            if notifications_send.send_single_notification(x):
                res = db_utils.get_or_create_by_unique(db_models.SentNotificationsLog, log_dict)
            else:
                logger.warning("Sending of notification failed.")



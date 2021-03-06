import datetime
from typing import Dict, Tuple, Set, List, Optional

import flask
from loguru import logger

import app.db_models as db_models
import app.utils.http_request_util
from app.utils.notifications.connection_types import Notification, SlackNotification, MailNotification
from app.utils.notifications.event_types import EventType
from config import NotificationsConfig
from app.utils.time_helper import time_source, datetime_to_timestamp, timestamp_to_datetime


class NotificationTypeExpiration(object):
    def __init__(self, single_res, notification_preferences):
        self.single_res = single_res
        self.notification_preferences = notification_preferences

        self.scan_order = single_res.ScanOrder
        self.certificate_chain = single_res.LastScan.result.certificate_information.received_certificate_chain_list
        self.days_remaining = (self.certificate_chain.not_after() - time_source.time()).days
        self.event_type = EventType.ClosingExpiration if self.days_remaining >= 0 else EventType.AlreadyExpired

    @staticmethod
    def check_condition_and_create_notifications(main_data, notification_preferences_by_scan_order_id: Dict[str, dict])\
            -> List[Notification]:
        scan_order_ids_expired, scan_order_ids_nearing_expiration = NotificationTypeExpiration.check_condition(main_data, notification_preferences_by_scan_order_id)
        notifications_to_send = NotificationTypeExpiration.create_notifications(main_data, notification_preferences_by_scan_order_id, scan_order_ids_expired, scan_order_ids_nearing_expiration)
        return notifications_to_send

    @staticmethod
    def check_condition(main_data, notification_preferences_by_scan_order_id: Dict[str, dict])\
            -> Tuple[Set, Set]:
        expiration_by_target_id = {}

        for single_res in main_data:
            try:
                key = single_res.Target.id
                val = single_res.ScanResults.certificate_information.received_certificate_chain_list.not_after()
                expiration_by_target_id[key] = val
            except AttributeError as e:
                logger.info(f"NotificationTypeExpiration: Handled AttributeError, most likely due to failed scan. Target id: {key}")

        scan_order_ids_expired = set()
        scan_order_ids_nearing_expiration = set()

        for single_res in main_data:
            try:
                scan_order_id = single_res.ScanOrder.id
                target_id = single_res.ScanOrder.target_id

                expires = expiration_by_target_id[target_id]
                notification_settings = notification_preferences_by_scan_order_id[scan_order_id]

                # todo: make filtering based on notification settings. Currently notifying about 1 day expire only
                if expires < time_source.time():
                    scan_order_ids_expired.add(single_res.ScanOrder.id)
                    continue
                if expires > time_source.time() + datetime.timedelta(
                        days=NotificationsConfig.start_sending_notifications_x_days_before_expiration):
                    continue

                notifications_x_days_before_expiration \
                    = extract_and_parse_notifications_x_days_before_expiration(notification_settings)

                certificate_chain = single_res.LastScan.result.certificate_information.received_certificate_chain_list
                not_after = certificate_chain.not_after()
                days_remaining = (not_after - time_source.time()).days

                if days_remaining in notifications_x_days_before_expiration:
                    scan_order_ids_nearing_expiration.add(single_res.ScanOrder.id)

            except KeyError as e:
                logger.info(f"NotificationTypeExpiration: Handled KeyError, most likely due to failed scan.")

        logger.info(f"scan_order_ids_expired orders ids: {scan_order_ids_expired}")
        logger.info(f"scan_order_ids_nearing_expiration ids: {scan_order_ids_nearing_expiration}")

        return scan_order_ids_expired, scan_order_ids_nearing_expiration

    @staticmethod
    def create_notifications(main_data, notification_preferences_by_scan_order_id: Dict[str, dict],
                             scan_order_ids_expired: Set, scan_order_ids_nearing_expiration: Set) -> List[Notification]:
        notifications_to_send = []

        for single_res in main_data:
            scan_order_id = single_res.ScanOrder.id

            if single_res.ScanOrder.id not in scan_order_ids_expired and \
                    single_res.ScanOrder.id not in scan_order_ids_nearing_expiration:
                continue

            final_pref = notification_preferences_by_scan_order_id[scan_order_id]
            new_rec = NotificationTypeExpiration(single_res, final_pref)

            notifications_to_send.extend(new_rec.craft_mails())
            notifications_to_send.extend(new_rec.craft_slacks())

        return notifications_to_send

    def event_id_generator(self):
        if self.event_type == EventType.AlreadyExpired:
            return f'{self.scan_order.id};{self.event_type};{self.certificate_chain.id};expired'
        return f'{self.scan_order.id};{self.event_type};{self.certificate_chain.id};{self.days_remaining}'

    def __craft_expiration_text(self):
        days_remaining = self.days_remaining

        if self.event_type == EventType.ClosingExpiration:
            return f"will expire in {days_remaining} days"
        else:
            return f"expired {abs(days_remaining)} days ago"

    def craft_mails(self) -> List[MailNotification]:
        email_preferences = self.notification_preferences.get("email")
        notifications_to_send = []
        crafted_text = self.craft_plain_text()

        for single_mail_connection in email_preferences:
            target: db_models.Target = self.single_res.Target

            res = MailNotification()
            res.event_id = self.event_id_generator()
            res.recipient_email = single_mail_connection["email"]

            res.subject = f"Certificate expiration notification ({target}) - certificate {self.__craft_expiration_text()}"

            res.text = crafted_text  # todo: use flask templating
            notifications_to_send.append(res)

        return notifications_to_send

    def craft_plain_text(self):
        # fallback when more specific function for channel is not available
        target: db_models.Target = self.single_res.Target

        scan_result_simplified: Optional[db_models.ScanResultsSimplified] = self.single_res.ScanResultsSimplified

        crafted_text = f'{target.human_readable_form()} uses certificate which should not be used after ' \
            f'{timestamp_to_datetime(scan_result_simplified.notAfter)}.\n' \
            f'The certificate {self.__craft_expiration_text()}\n'\
            f'More information available at {app.utils.http_request_util.get_web_ui_address()}#/listTargets/{target.id}'
        return crafted_text

    def craft_slacks(self) -> List[SlackNotification]:
        channel_preferences = self.notification_preferences.get("slack")
        notifications_to_send = []
        crafted_text = self.craft_plain_text()

        for single_slack_connection in channel_preferences:
            res = SlackNotification()
            res.event_id = self.event_id_generator()
            res.connection_id = single_slack_connection["id"]
            res.text = crafted_text
            notifications_to_send.append(res)

        return notifications_to_send


def extract_and_parse_notifications_x_days_before_expiration(pref: dict) -> set:
    notifications_x_days_before_expiration = set()

    notifications_x_days_before_expiration_string =\
        pref.get("notifications_x_days_before_expiration",
                 NotificationsConfig.default_pre_expiration_periods_in_days)
    notifications_x_days_before_expiration_list_of_strings = notifications_x_days_before_expiration_string.split(",")

    for x in notifications_x_days_before_expiration_list_of_strings:
        if x:
            notifications_x_days_before_expiration.add(int(x))

    return notifications_x_days_before_expiration

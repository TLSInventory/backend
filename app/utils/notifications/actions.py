import jsons
from typing import List
from loguru import logger

from app.utils.notifications.user_preferences import \
    NotificationChannelOverride, filter_ids_of_notification_settings_user_can_see, \
    CONNECTION_DB_MODELS_TYPES, mail_add


import app.utils.db.advanced as db_utils_advanced
import app.db_schemas as db_schemas
import app.db_models as db_models


def additional_channel_email_actions(email_pref: dict, user_id: int) -> bool:
    ADD_NEW_EMAILS_FIELD = "add_new_emails"

    emails_to_be_added = getattr(email_pref, ADD_NEW_EMAILS_FIELD, None)
    if emails_to_be_added:
        try:
            new_mails_or_exception_msg, status_code = mail_add(user_id, emails_to_be_added)
            if status_code != 200:
                raise Exception(new_mails_or_exception_msg)
            delattr(email_pref, ADD_NEW_EMAILS_FIELD)

            new_emails_ids_to_force_enable = [x.id for x in new_mails_or_exception_msg]
            email_pref.force_enabled_ids.extend(new_emails_ids_to_force_enable)
        except Exception as e:
            logger.error(f"Error adding new emails for target: {e}")
            return False

    return True


def set_notification_settings_raw_single_target(user_id: int, target_id: int, notifications: dict):
    return set_notification_settings_raw_multiple_target_ids(user_id, [target_id], notifications)


def set_notification_settings_raw_multiple_target_ids(user_id: int, target_ids: List[int], notifications: dict):
    NOTIFICATION_CHANNELS = CONNECTION_DB_MODELS_TYPES.keys()

    new_notification_settings = {}

    for single_channel in NOTIFICATION_CHANNELS:
        if notifications.get(single_channel) is None:
            continue
        new_notification_settings[single_channel] = jsons.load(notifications.get(single_channel),
                                                               NotificationChannelOverride)

        if single_channel == "email":
            additional_channel_email_actions(new_notification_settings[single_channel], user_id)

    for single_channel in NOTIFICATION_CHANNELS:
        settings_current_channel = new_notification_settings[single_channel]
        settings_current_channel.force_enabled_ids = \
            filter_ids_of_notification_settings_user_can_see(
                user_id, single_channel, settings_current_channel.force_enabled_ids)
        settings_current_channel.force_disabled_ids = \
            filter_ids_of_notification_settings_user_can_see(
                user_id, single_channel, settings_current_channel.force_disabled_ids)

        if jsons.dumps(settings_current_channel) == jsons.dumps(NotificationChannelOverride()):
            del new_notification_settings[single_channel]

    new_notification_settings_json_str = jsons.dumps(new_notification_settings)

    if len(new_notification_settings):
        for target_id in target_ids:
            notifications_override: db_models.ConnectionStatusOverrides = \
                db_utils_advanced.generic_get_create_edit_from_data(
                    db_schemas.ConnectionStatusOverridesSchema,
                    {"target_id": target_id, "user_id": user_id})
            notifications_override.preferences = new_notification_settings_json_str
        db_models.db.session.commit()

    return True

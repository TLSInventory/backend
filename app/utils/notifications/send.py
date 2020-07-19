from loguru import logger
from notifiers import get_notifier
import app.db_models as db_models
from config import MailConfig


from app.utils.notifications.connection_types import Notification, SlackNotification, Channels, MailNotification, \
    StoredPlainTextNotification


def send_single_notification(x: Notification) -> bool:
    res = None

    if x.channel == Channels.Mail:
        x: MailNotification
        res = email_send_msg(x.recipient_email, x.text, x.subject)

    if x.channel == Channels.Slack:
        x: SlackNotification
        slack_connection_id = x.connection_id
        slack_connection = db_models.db.session.query(db_models.SlackConnections).get(slack_connection_id)
        res = slack_send_msg(slack_connection, x.text)

    if res is not None:
        return res.ok

    if x.channel in [Channels.STORED_PLAINTEXT_CHANNELS_ALL, Channels.RSS, Channels.UI]:
        x: StoredPlainTextNotification
        res = x.transform_to_db_object()
        db_models.db.session.add(res)
        db_models.db.session.commit()
        return True

    return False


def slack_send_msg(slack_configuration: db_models.SlackConnections, msg: str):
    return slack_send_msg_via_webhook(slack_configuration.webhook_url, msg)


def slack_send_msg_via_webhook(webhook: str, msg: str):
    p = get_notifier('slack')
    return p.notify(webhook_url=webhook, message=msg)


def email_send_msg(to: str, msg: str, subject="Notification from TLSInventory"):
    if not MailConfig.enabled:
        logger.info("Notification not send, because MailConfig is disabled.")
        return None

    if MailConfig.use_gmail:
        return get_notifier('gmail').notify(to=to, message=msg, subject=subject,
                                            username=MailConfig.username, password=MailConfig.password)

    email = get_notifier('email')
    smtp_config = {
        "host": MailConfig.hostname,
        "port": MailConfig.port,
        "tls": MailConfig.tls,

        "username": MailConfig.username,
        "password": MailConfig.password,

        "from": MailConfig.sender_email,
        "html": False,
    }
    return email.notify(to=to, message=msg, subject=subject, **smtp_config)

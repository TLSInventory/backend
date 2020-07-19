import abc
from enum import Enum
from typing import Optional

import app.db_models as db_models


class Channels (Enum):
    Mail = 1
    Slack = 2
    RSS = 3
    UI = 4
    STORED_PLAINTEXT_CHANNELS_ALL = 5  # Currently that means RSS and UI


class NotificationsAbstract(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def notification_id(self) -> str:
        """Creates unique id of the Notification including the destination (email address, slack, etc).
        Can implemented for example by concating event_id and hash of properties unique to subclass.
        """


class Notification(NotificationsAbstract, abc.ABC):
    def __init__(self, channel: Channels, text: Optional[str] = None):
        self.event_id: int  # this is so that we can match Slack and Mail notification for the same event
        self.channel: Channels = channel
        self.text: str = text or ""


class MailNotification(Notification):
    def __init__(self):
        super().__init__(Channels.Mail)
        self.recipient_email: str
        self.subject: str

    def notification_id(self) -> str:
        return f'{self.event_id};{self.recipient_email}'


class SlackNotification(Notification):
    def __init__(self):
        super().__init__(Channels.Slack)
        self.connection_id: int = None

    def notification_id(self) -> str:
        return f'{self.event_id};{self.connection_id}'


class StoredPlainTextNotification(Notification):
    def __init__(self):
        super().__init__(Channels.STORED_PLAINTEXT_CHANNELS_ALL)
        self.user_id: int
        self.target_id: int

    def notification_id(self) -> str:
        return f'{self.event_id};{self.user_id}'

    def transform_to_db_object(self) -> db_models.PlainTextNotification:
        res = db_models.PlainTextNotification()

        res.event_id = self.event_id
        res.channel = self.channel.name
        res.msg = self.text

        res.user_id = self.user_id
        res.target_id = self.target_id
        res.notification_id = self.notification_id()

        return res


class UINotification(StoredPlainTextNotification):
    def __init__(self):
        super().__init__(Channels.UI)


class RSSNotification(StoredPlainTextNotification):
    def __init__(self):
        super().__init__(Channels.RSS)

from enum import Enum


class EventType (Enum):
    ClosingExpiration = 1
    AlreadyExpired = 2
    GradeLowered = 3

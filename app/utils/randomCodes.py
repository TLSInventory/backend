import datetime
import string
from enum import Enum
import random
from typing import Union, Tuple

import app.db_models as db_models


class ActivityType(Enum):
    SLACK = 1
    MAIL_VALIDATION = 2
    PASSWORD_RESET = 3


def gen_random_code(n=16):
    return ''.join(random.choice(string.ascii_letters) for i in range(n))


def create_and_save_random_code(activity: ActivityType, user_id: int, expire_in_n_minutes: int, params: str = None) -> str:
    if params is None:
        params = ""

    res = db_models.TmpRandomCodes()
    res.user_id = user_id
    res.activity = activity.name
    res.expires = db_models.datetime_to_timestamp(datetime.datetime.now() + datetime.timedelta(minutes=expire_in_n_minutes))
    res.code = gen_random_code()
    res.params = params
    db_models.db.session.add(res)
    db_models.db.session.commit()
    return res.code


def validate_code(db_code: str, activity: ActivityType, user_id=None)\
        -> Union[Tuple[bool, str], Tuple[bool, db_models.TmpRandomCodes]]:
    query = db_models.db.session \
        .query(db_models.TmpRandomCodes) \
        .filter(db_models.TmpRandomCodes.code == db_code) \
        .filter(db_models.TmpRandomCodes.activity == activity.name) \
        .filter(db_models.TmpRandomCodes.expires >= db_models.datetime_to_timestamp(datetime.datetime.now()))

    if user_id:
        query = query.\
            filter(db_models.TmpRandomCodes.user_id == user_id)

    res: db_models.TmpRandomCodes = query.first()

    db_models.logger.warning(f'TmpRandomCode obj {res}')

    if res is None:
        msg = """Code either:
               - doesn't exist
               - has expired
               - is being used for different purpose than it was originally issued
               """
        if user_id:
            msg += "- belongs to different user than is currently signed in\n"

        return False, msg


    return True, res


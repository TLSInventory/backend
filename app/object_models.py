from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import List

import marshmallow.fields
import marshmallow_sqlalchemy.fields

import app.db_schemas as db_schemas
import app.db_models as db_models
import app.utils.db.advanced as db_utils_advanced


class TargetWithExtra(object):
    def __init__(self, target_definition: db_models.Target, extra: dict = None):
        self.target_definition: db_models.Target = target_definition
        self.extra = extra
        if self.extra is None:
            self.extra = {}

    def __repr__(self):
        # return f"TargetWithExtra(target={self.target_definition}, extra={self.extra})"
        return json.dumps(self.json_repr())

    def json_repr(self):
        return {"target_definition": repr(self.target_definition), "extra": self.extra}

    @staticmethod
    def transient_from_dict(data: dict) -> TargetWithExtra:
        target = db_utils_advanced.generic_get_create_edit_from_data(db_schemas.TargetSchema,
                                                                     data.get("target_definition", dict()),
                                                                     transient_only=True)
        extra = data.get("extra", dict())
        return TargetWithExtra(target, extra)


def load_json_to_targets_with_extra(json_string: str) -> List[TargetWithExtra]:
    data_arr = json.loads(json_string)
    twe = []
    for single_twe_dict in data_arr:
        single_twe_obj = TargetWithExtra.transient_from_dict(single_twe_dict)
        twe.append(single_twe_obj)
    return twe


class TargetWithExtraSchema(marshmallow.Schema):
    #target_definition = marshmallow.fields.Dict(required=True)
    target_definition = marshmallow_sqlalchemy.fields.Nested(db_schemas.TargetSchema)
    extra = marshmallow.fields.Dict(missing=dict())
    # todo: add validation to TargetWithExtraSchema. The validation can't use DB as it's also used on sensor.
    # todo: I'm not sure how to do SQLAlchemySchema without table and regular marshmallow.Schema doesn't support transient param.


@dataclass
class ScanResultResponse(object):
    results: list = field(default_factory=list)
    # results is List[dict], but jsons seems to have problem with Typing.
    results_attached: bool = False
    empty_job: bool = False

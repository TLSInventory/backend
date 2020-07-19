from typing import Optional

import app
import app.db_models as db_models
import app.db_schemas as db_schemas
from app.utils.db.basic import get_or_create_or_update_by_unique
from loguru import logger


def generic_get_create_edit_from_data(schema: db_schemas.SQLAlchemyAutoSchema, data: dict, transient_only=False,
                                      get_only=False) -> Optional[db_models.Base]:
    # Warning: Unless get_only=True, this function overwrites attributes in DB to default used in schema load,
    # if the attributes are not specified in data.
    # Warning: This overwrites excluded filds, most commonly ID.
    schema_instance = schema()
    res_transient = schema_instance.load(data, transient=True)  # this validates input
    return generic_get_create_edit_from_transient(schema, res_transient, transient_only, get_only)


def generic_get_create_edit_from_transient(schema: db_schemas.SQLAlchemyAutoSchema,
                                           model_transient: db_models.Base,
                                           transient_only=False,
                                           get_only=False) -> Optional[db_models.Base]:
    # Warning: Unless get_only=True, this function overwrites attributes in DB to default used in schema load,
    # if the attributes are not specified in data.
    # Warning: This overwrites excluded filds, most commonly ID.
    if transient_only:
        return model_transient
    schema_instance = schema()
    res_dict = schema_instance.dump(model_transient)
    return get_or_create_or_update_by_unique(schema.Meta.model, res_dict, get_only=get_only)


def generic_delete_from_data(schema: db_schemas.SQLAlchemyAutoSchema, data: dict) -> db_models.Base:
    res = generic_get_create_edit_from_data(schema, data, get_only=True)
    try:
        app.db.session.delete(res)
        app.db.session.commit()
    except Exception as e:
        logger.warning(f'Delete failed for model {res}')
        return False
    return True

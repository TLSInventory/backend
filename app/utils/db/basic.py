import enum
from typing import Tuple, Optional, Dict

from loguru import logger
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound
import app
import copy
import config
import app.db_models as db_models


# This is generalized version of get_or_create. Previously my code used specific variant for each class.
# This comes from Erik Taubeneck and his series of block posts about this topic.
# https://skien.cc/blog/2014/02/06/sqlalchemy-and-race-conditions-follow-up-on-commits-and-flushes/.
# https://github.com/eriktaubeneck/heroku-test
def get_one_or_create(model,
                      create_method='',
                      create_method_kwargs=None,
                      **kwargs) -> Tuple[app.db.Model, bool]:
    try:
        return model.query.filter_by(**kwargs).one(), True
    except NoResultFound:
        kwargs.update(create_method_kwargs or {})
        created = getattr(model, create_method, model)(**kwargs)
        try:
            app.db.session.add(created)
            app.db.session.commit()
            return created, False
        except IntegrityError:
            app.db.session.rollback()
            return app.db.session.query(model).filter_by(**kwargs).one(), True


def get_one_or_create_from_object(obj: app.db.Model) -> Tuple[app.db.Model, bool]:  # todo: remove this function
    logger.critical("Deprecated: This function should no longer be used anywhere")
    kwargs = {x: vars(obj)[x] for x in vars(obj) if not x.startswith("_")}
    b = type(obj)
    return get_one_or_create(type(obj), **kwargs)


def dict_filter_to_class_variables(class_type: app.db.Model, obj_from_json: dict) -> dict:
    attr_names: list = class_type.attribute_names()
    if "id" in attr_names:
        attr_names.remove("id")
    return dict_filter_columns(attr_names, obj_from_json)


def dict_filter_columns(columns_to_keep: list, obj: dict) -> dict:
    return {x: obj[x] for x in obj if x in columns_to_keep}


def split_array_to_tuple(a: str) -> Tuple:
    list_str = a[:].replace("[", "").replace("]", "")
    list1 = list_str.split(",")
    list2 = [x for x in list1 if len(x)]
    list_as_tuple = tuple(map(int, list2))
    return list_as_tuple


def merge_dict_with_copy_and_overwrite(a: dict, b: dict) -> dict:
    a = copy.deepcopy(a)
    b = copy.deepcopy(b)
    a.update(b)  # Important: This includes overwriting anything in a, that is also in b. It's used as security feature.
    return a


def get_search_by(model: app.db.Model, kwargs: dict) -> Tuple[dict, dict]:
    kwargs_original = copy.deepcopy(kwargs)
    kwargs = dict_filter_to_class_variables(model, kwargs)
    if len(kwargs) != len(kwargs_original):
        logger.debug(
            f"get_or_create_or_update_by_unique received kwargs with invalid vars for the {model}, removed vars were {(set(kwargs_original) - set(kwargs))}")
    if kwargs.get("id", None):
        logger.warning(
            f"get_or_create_or_update_by_unique received kwargs including id for model {model}. Removing.")

    search_by = kwargs
    if hasattr(model, '__uniqueColumns__'):
        search_by = dict_filter_columns(model.__uniqueColumns__, kwargs)

    return kwargs, search_by


def get_or_create_by_unique(model: app.db.Model, kwargs: dict, search_by: Optional[dict] = None, get_only=False)\
        -> Tuple[app.db.Model, bool]:
    if search_by is None:
        _, search_by = get_search_by(model, kwargs)

    logger.debug(f"get_or_create_or_update_by_unique searching model {model} by {search_by}")

    if config.CacheConfig.enabled:
        if False:
            return  # todo: Cache can be safely implemented here. If result is found in cache, return, otherwise let DB handle it.

    try:
        return model.query.filter_by(**search_by).one(), True
    except NoResultFound:
        if get_only:
            return None, False
        return get_one_or_create(model, **kwargs)


def get_or_create_or_update_by_unique(model: app.db.Model, kwargs: dict, get_only=False) -> Optional[app.db.Model]:
    kwargs, search_by = get_search_by(model, kwargs)
    res, existing = get_or_create_by_unique(model, kwargs, search_by, get_only=get_only)

    if not existing or get_only:
        if not get_only:  # this means the record is newly inserted
            if hasattr(res, 'on_modification') and res.on_modification:
                actions_on_modification(res)
        return res

    something_changed = False
    for key in kwargs:
        if getattr(res, key) != kwargs[key]:
            if isinstance(getattr(res, key), enum.Enum) and getattr(res, key).name == kwargs[key]:
                continue
            # logger.warning(f"{getattr(res, key)} != {kwargs[key]}")
            # logger.warning(f"{getattr(res, key).name}")
            setattr(res, key, kwargs[key])
            something_changed = True


    if something_changed:
        app.db.session.commit()
        if hasattr(res, 'on_modification') and res.on_modification:
            actions_on_modification(res)
    else:
        pass
    app.db.session.commit()  # it's possible that some change happened but isn't yet commited. In such a case the
    # something_changed detection would fail.

    return res


def actions_on_modification(res):
    if isinstance(res, db_models.ScanOrder):
        scan_order_minimal_recalculate(res.target_id)


def scan_order_minimal_recalculate(target_id: int):
    app.scan_scheduler.update_scan_order_minimal_for_target(target_id)
    db_models.LastScan.create_if_not_existent(target_id=target_id)


def set_attr_if_none(x: Dict, attr_name: str, default_val):
    if x.get(attr_name, None) is None:
        x[attr_name] = default_val

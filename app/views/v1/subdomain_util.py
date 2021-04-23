from typing import Set

import json

import flask_jwt_extended
from flask import request, url_for

import app.utils.authentication_utils as authentication_utils
import app.actions as actions
import app.db_models as db_models

from . import bp
from app.utils.ct_search import get_subdomains_from_ct
from app.actions.add_targets import add_targets


@bp.route(
    "/api_add_subdomains/<int:target_id>",
    methods=["POST", "DELETE"]
)
@flask_jwt_extended.jwt_required
def api_add_subdomains(target_id: int):
    user_id = authentication_utils.get_user_id_from_current_jwt()
    target = actions.get_target_from_id_if_user_can_see(target_id, user_id)
    data = json.loads(request.data)

    if target is None:
        return "You do not have permission to track this target.", 400

    fetched_subdomains = set(get_subdomains_from_ct(target.hostname))
    tracked_subdomains = get_tracked_subdomains_by_hostname(
        target.hostname,
        user_id
    )

    subdomains = fetched_subdomains - tracked_subdomains

    amount_of_subdomains = len(subdomains)

    subdomain_ids = add_targets(subdomains, user_id, data)

    return f"Successfully added {len(subdomain_ids)} subdomains.", amount_of_subdomains, 200


def get_tracked_subdomains_by_hostname(hostname: str, user_id: int)\
        -> Set[str]:
    # wait for review from Ondra
    # assumes there is a relationship between Target and ScanOrder
    db_response = db_models.db.session.query(db_models.Target) \
        .outerjoin(db_models.ScanOrder) \
        .filter(db_models.ScanOrder.user_id == user_id) \
        .filter(db_models.Target.hostname.like(f"%{hostname}")) \
        .all()

    return set(map(lambda target: target.hostname, db_response))

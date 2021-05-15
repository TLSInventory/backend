from typing import Set, Tuple

import json

import flask_jwt_extended
from flask import request, url_for

import app.utils.authentication_utils as authentication_utils
import app.actions as actions
import app.db_models as db_models

from . import bp
from app.utils.ct_search import get_subdomains_from_ct
from app.actions.add_targets import add_targets


def add_subdomains(target_id: int, user_id: int, data) -> Tuple[str, int, int]:
    # new table with primary key (user_id, target_id) -> periodically rescan
    # SSCT do configu, aby sa nastavila periodicita
    # filtorvat podla najstarsieho timestamp
    target = actions.get_target_from_id_if_user_can_see(target_id, user_id)

    if target is None:
        return "You do not have permission to track this target.", 0, 400

    if data is None:  # dummy data for searching and enqueuing new subdomains
        data = {
                "scanOrder": {"active": None, "periodicity": 43200},
                "target": {
                    "hostname": f"{target.hostname}",
                    "id": None,
                    "ip_address": None,
                    "port": None,
                    "protocol": "HTTPS",
                },
            }

    subdomains = cron_subdomain_lookup(target, user_id)
    subdomain_ids = add_targets(list(subdomains), user_id, data)

    return f"Successfully added {len(subdomain_ids)} subdomains", len(subdomain_ids), 200


@bp.route("/api_add_subdomains/<int:target_id>", methods=["POST", "DELETE"])
@flask_jwt_extended.jwt_required
def api_add_subdomains(target_id: int):
    user_id = authentication_utils.get_user_id_from_current_jwt()
    data = json.loads(request.data)

    return add_subdomains(target_id, user_id, data)


def get_tracked_subdomains_by_hostname(
    hostname: str, user_id: int
) -> Set[str]:
    # assumes there is a relationship between Target and ScanOrder
    db_response = (
        db_models.db.session.query(db_models.Target)
        .outerjoin(db_models.ScanOrder)
        .filter(db_models.ScanOrder.user_id == user_id)
        .filter(db_models.Target.hostname.like(f"%{hostname}"))
        .all()
    )

    return set(map(lambda target: target.hostname, db_response))


def cron_subdomain_lookup(target: db_models.Target, user_id: int) -> Set[str]:
    tracked_subdomains = get_tracked_subdomains_by_hostname(target.hostname, user_id)
    all_subdomains = set(get_subdomains_from_ct(target.hostname))
    return all_subdomains - tracked_subdomains

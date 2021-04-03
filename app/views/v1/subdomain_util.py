import json

import flask_jwt_extended
from flask import request, url_for

import app.utils.authentication_utils as authentication_utils
import app.actions as actions

from . import bp
from app.utils.ct_search import get_subdomains_from_ct
from app.actions.add_targets import add_targets


@bp.route(
    "/add_subdomains/<int:target_id>",
    methods=["POST", "DELETE"]
)
@flask_jwt_extended.jwt_required
def api_add_subdomains(target_id: int):
    user_id = authentication_utils.get_user_id_from_current_jwt()
    target = actions.get_target_from_id_if_user_can_see(target_id, user_id)
    data = json.loads(request.data)

    if target is None:
        return "You do not have permission to track this target.", 400

    subdomains = set(get_subdomains_from_ct(target.hostname))

    # tracked_subdomains = retrieve existing subdomains from DB

    # subdomains = subdomians - set(tracked_subdomains)

    subdomain_ids = add_targets(subdomains, user_id, data)

    return f"Successfully added {len(subdomain_ids)} subdomains.", 200



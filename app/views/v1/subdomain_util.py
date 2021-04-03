# TODO:
# pamatat si subdomeny v databazi, kazdu chvilu sa bude volat ct search
# db_models.Target, scanOrder a vlastna tabulka v databazi
# api_target -> vyclenit co potrebujem aj tu do separatnej metody
# get_target_id_if_user_can_see_it -> vrati Target z db_models, pouzitie rovnake ako v api_target

# testy spravit podla tests/scan_scheduler_test.py
import json

from flask import request

import app.utils.authentication_utils as authentication_utils
import app.actions as actions

from . import bp
from app.utils.ct_search import get_subdomains_from_ct
from app.actions.add_targets import add_targets


@bp.route(
    "/add_subdomain/<int:target_id>",
    methods=["POST", "DELETE"]
)
def add_subdomains(target_id: int):
    user_id = authentication_utils.get_user_id_from_current_jwt()
    target = actions.get_target_from_id_if_user_can_see(target_id, user_id)
    data = json.loads(request.data)

    if target is None:
        return "You do not have permission to track this target.", 400

    subdomains = get_subdomains_from_ct(target.hostname)

    subdomain_ids = add_targets(subdomains, user_id, data)

    return f"Successfully added {len(subdomain_ids)} subdomains.", 200



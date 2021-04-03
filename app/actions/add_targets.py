from typing import List
import copy

import app.utils.db.basic as db_utils
import app.utils.db.advanced as db_utils_advanced
import app.db_schemas as db_schemas


def add_targets(hostnames: List[str], user_id, data):
    ids = set()

    for hostname in hostnames:
        new_target_def = copy.deepcopy(data["target"])
        new_target_def["hostname"] = hostname

        target = db_utils_advanced.generic_get_create_edit_from_data(
            db_schemas.TargetSchema,
            new_target_def
        )

        ids.add(target.id)

        if data.get("scanOrder"):
            scan_order_def = db_utils.merge_dict_with_copy_and_overwrite(
                data.get("scanOrder", {}),
                {"target_id": target.id, "user_id": user_id}
            )

            db_utils_advanced.generic_get_create_edit_from_data(
                db_schemas.ScanOrderSchema,
                scan_order_def
            )

    return ids

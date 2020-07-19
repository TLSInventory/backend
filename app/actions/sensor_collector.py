import jsons
import requests
from loguru import logger

import app.utils.files
import config
import app.object_models as object_models


def sslyze_save_scan_results_from_obj(obj_to_save: object_models.ScanResultResponse, comes_from_http: bool = False)\
        -> bool:
    if not obj_to_save.results_attached:
        return False
    results = obj_to_save.results


    if config.SensorCollector.SEND_RESULTS_OVER_HTTP:
        if comes_from_http:
            logger.error("Received sslyze scan results to insert but SensorCollector.SEND_RESULTS_OVER_HTTP is enabled here.\n"
                         "Canceling outbound request, forwarding is not implemented as prevention of endless cycle.")
        else:
            # todo: do it through app context if it's not sending to collector

            endpoint_url = f'{config.SensorCollector.BASE_URL}/api/v1/sslyze_import_scan_results'
            if config.SensorCollector.KEY:
                endpoint_url += f"/{config.SensorCollector.KEY}"

            dict_to_send = jsons.dump(obj_to_save)
            # dict_to_send_string = jsons.dumps(obj_to_save)
            # app.utils.files.write_to_file("tmp/dict_to_send_string3.json", dict_to_send_string)
            r = requests.post(endpoint_url, json=dict_to_send)
            print(r.status_code, r.text)
            # todo: do something with status code

    if config.SensorCollector.SEND_RESULTS_TO_LOCAL_DB:
        for single_result in results:
            try:
                import app.utils.sslyze.parse_result as sslyze_parse_result
                scan_result = sslyze_parse_result.insert_scan_result_into_db(single_result)
            except Exception as e:
                logger.warning("Failed inserting or parsing scan result. Skipping it.")
                logger.exception(e)
                if not config.SslyzeConfig.soft_fail_on_result_parse_fail:
                    raise

    return True


def sslyze_save_scan_results(scan_dict: dict) -> bool:
    if not scan_dict.get('results_attached', False):
        return False

    res = object_models.ScanResultResponse(
        results_attached=scan_dict.get('results_attached', False),
        results=scan_dict.get("results", [])
    )

    return sslyze_save_scan_results_from_obj(res)

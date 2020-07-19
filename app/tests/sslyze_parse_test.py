import os
from loguru import logger

from app.utils.files import read_from_file
import app.actions.sensor_collector as sensor_collector


def try_to_insert_all_scan_results():
    path = "tmp/scan_result"
    if not os.path.exists(path):
        logger.warning("No folder")
        return
    for filename in os.listdir(path):
        # logger.warning(filename)
        result_string = read_from_file(f'{path}/{filename}')
        a = {
            "results_attached": True,
            "results": [result_string]
        }
        sensor_collector.sslyze_save_scan_results(a)

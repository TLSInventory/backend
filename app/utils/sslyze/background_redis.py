import jsons
from loguru import logger
import redis
import rq
import app.actions.sensor_collector
import app.object_models as object_models
import app.utils.sslyze.scanner as sslyze_scanner
import os

from config import SslyzeConfig, SensorCollector


def file_module_string_from_path():
    file_path = os.path.abspath(__file__)
    cwd_path = f'{os.getcwd()}/'
    # print(f'file path {file_path}')
    # print(f'cwd path {cwd_path}')
    module_path_string = file_path[:].replace(cwd_path, "").replace("/", ".").replace(".py", "")
    return module_path_string


def redis_sslyze_fetch_job(job_id: str) -> rq.job:
    from flask import current_app
    try:
        queue: rq.queue = current_app.sslyze_task_queue
        return queue.fetch_job(job_id)
    except (redis.exceptions.RedisError, rq.exceptions.NoSuchJobError):
        return "Redis error", 500


def redis_sslyze_enqueu(ntwe_json_string: str) -> str:
    from flask import current_app
    queue: rq.queue = current_app.sslyze_task_queue
    module_and_function_string = 'app.utils.sslyze.background_redis.redis_sslyze_scan_domains_to_json'
    expected_module_string = file_module_string_from_path()
    if expected_module_string not in module_and_function_string:
        logger.warning("The background_redis static string is not equal to the expected one.\n"
            f"{module_and_function_string}\n{expected_module_string}")

    job: rq.job = queue.enqueue(module_and_function_string, ntwe_json_string)
    return job.get_id()


def redis_sslyze_scan_domains_to_json(domains_json: str) -> str:
    logger.debug(f"config.SensorCollector.SEND_RESULTS_OVER_HTTP: {SensorCollector.SEND_RESULTS_OVER_HTTP}\n"
         f"os.environ.get('SENSOR_COLLECTOR_SEND_RESULTS_OVER_HTTP') {os.environ.get('SENSOR_COLLECTOR_SEND_RESULTS_OVER_HTTP')}")
    twe = object_models.load_json_to_targets_with_extra(domains_json)
    list_of_results_as_json = sslyze_scanner.scan_domains_to_arr_of_dicts(twe)
    answer = {'results_attached': True, 'results': list_of_results_as_json}
    app.actions.sensor_collector.sslyze_save_scan_results(answer)
    return jsons.dumps(answer)

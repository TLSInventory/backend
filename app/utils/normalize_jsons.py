import json
from loguru import logger
from app.utils.files import *


def normalize_file(filename: str):
    json_string = read_from_file(filename)
    json_obj = json.loads(json_string)
    json_string_result = json.dumps(json_obj, indent=3, sort_keys=True)
    write_to_file(filename+"_normalized.json", json_string_result)


@logger.catch
def run():
    normalize_file("tmp/from_db_marshmallow_ScanResults.json")
    normalize_file("tmp/test_copy.out.json")


if __name__ == '__main__':
    run()

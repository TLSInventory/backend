import json

import app.db_models
import app.db_schemas
import app.utils.files as files


def test_extract_from_db():
    cls_name = "ScanResults"  # security: cls_name MUST NOT be dynamically assigned to
    cls = eval("app.db_models."+cls_name)  # security:
    cls_schema = eval("app.db_schemas."+cls_name+"Schema")  # security:
    res = app.db.session.query(cls).all()
    schema = cls_schema(many=True)
    json_dict = schema.dump(res)

    json_string = json.dumps(json_dict, indent=3)
    files.write_to_file(f"tmp/from_db_marshmallow_{cls_name}.json", json_string)
    return json_string

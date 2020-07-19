from pathlib import Path


def write_to_file(filename: str, content: str):
    with open(filename, "w") as f:
        f.write(content)


def read_from_file(filename: str) -> str:
    with open(filename, "r") as f:
        return f.read()


def unescape_json1(json_string):
    return json_string \
        .replace('\\n', '\n') \
        .replace('"{', '{') \
        .replace('}"', '}') \
        .replace('\\"', '"')


def create_folder_if_doesnt_exist(path: str):
    Path(path).mkdir(parents=True, exist_ok=True)

import json
import requests
from typing import List, Dict
from loguru import logger
from config import ImportConfig
from app.utils.files import write_to_file

"""
# Usage example
from utils.ct_search import get_subdomains_from_ct

print(get_subdomains_from_ct("borysek.eu"))
"""


# This is based on my old PoC for certificate transparency search.
# https://github.com/BorysekOndrej/certificate-transparency-search/blob/master/python/cts.py
# The version bellow does not have all the functionality of the PoC, because it doesn't need it.
def get_subdomains_from_ct(domain: str) -> List[str]:
    # This is wrapper for future expansion
    if not ImportConfig.crt_sh:
        logger.info("Crt.sh is disabled in the config file")
        return []
    resp = crt_sh(domain)
    identities_and_ids = get_identities_and_ids(resp)
    identities = [x for x in identities_and_ids]
    subdomains = [x for x in identities if x.endswith(domain)]
    return subdomains


def crt_sh(domain) -> Dict:
    pattern = f"%.{domain}"

    req_url = f"https://crt.sh/?q={pattern}&output=json"
    try:
        req = requests.get(req_url)
    except Exception as e:
        logger.exception(e)

    if req.status_code != 200:
        logger.error("""
        Request for quick/basic search failed.
        Possible problems: network issues or too many certs match pattern.
        """)

    if ImportConfig.crt_sh_debug:
        write_to_file("tmp/crt_sh_debug.json", req.text)

    data = json.loads(req.text)
    if data is None or len(data) == 0:
        logger.warning("200 OK but no data from crt.sh. Possibly no certificates or failed parsing?")
        return {}

    if ImportConfig.crt_sh_debug:
        write_to_file("tmp/crt_sh_debug_beautified.json", json.dumps(data, indent=3))

    return data


def get_identities_and_ids(data) -> Dict:
    subdomains = {}
    for single_cert in data:
        cert_id = single_cert["id"]
        name_value = single_cert["name_value"]
        matching_identities = name_value.split("\n")
        for single_identity in matching_identities:
            subdomains[single_identity] = subdomains.get(single_identity, [])
            subdomains[single_identity].append(cert_id)
    return subdomains

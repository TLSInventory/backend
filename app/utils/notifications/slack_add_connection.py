from slack import WebClient

import app.db_models as db_models
import app.db_schemas as db_schemas
import app.utils.db.advanced as db_utils_advanced

from config import SlackConfig
from loguru import logger


# todo: consider reworking code validation to not use official Slack library, because it's currently the only use-case
def validate_code_and_save(auth_code, user_id) -> bool:
    # This function is adopted from Slack documentation.

    # An empty string is a valid token for this request
    client = WebClient(token="")

    # Request the auth tokens from Slack
    response = client.oauth_v2_access(
        client_id=SlackConfig.client_id,
        client_secret=SlackConfig.client_secret,
        code=auth_code,
        redirect_uri=SlackConfig.local_post_install_url
    )
    if response.data["ok"]:
        save_slack_config(response.data, user_id)
    else:
        logger.warning(response.data)
    logger.debug((response.data, response.status_code))
    return response.data["ok"]


def save_slack_config(response_data, user_id):
    new_slack_connection = db_models.SlackConnections()
    new_slack_connection.user_id = user_id
    new_slack_connection.channel_name = response_data["incoming_webhook"]["channel"]
    new_slack_connection.channel_id = response_data["incoming_webhook"]["channel_id"]
    new_slack_connection.access_token = response_data["access_token"]
    new_slack_connection.webhook_url = response_data["incoming_webhook"]["url"]
    new_slack_connection.team_id = response_data["team"]["id"]
    new_slack_connection.team_name = response_data["team"]["name"]

    res = db_utils_advanced.generic_get_create_edit_from_transient(db_schemas.SlackConnectionsSchema,
                                                                   new_slack_connection)
    logger.debug(str(res))

    return "ok", 200

from flask import Blueprint

bp = Blueprint('apiV2', __name__)

from . import scan_results, scan_info

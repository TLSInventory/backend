from flask import Blueprint

bp = Blueprint('apiDebug', __name__)

from . import misc

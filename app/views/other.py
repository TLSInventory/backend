from flask import Blueprint
bp = Blueprint('otherRoutes', __name__)

from flask import render_template


@bp.route('/')
@bp.route('/index')
def index():
    # test_arg = [{"title": "title1", "content": "content1"}, {"title": "title2", "content": "content2"}]
    test_arg = []
    return render_template('index.html', title='Test index page', test_arg=test_arg)


@bp.route('/dashboard')
def dashboard_index():
    return render_template('index.html', title='Dashboard', test_arg=[])


@bp.route('/dashboard/login')
def dashboard_login():
    return render_template('index.html', title='Dashboard login', test_arg=[])


@bp.route('/debug/html/batch_direct_scan')
def debug_batch_direct_scan_html():
    return render_template('debug_html/batch_direct_scan.html')


@bp.route('/debug/<string:domain>')
@bp.route('/debug/')
def debug_overview(domain="borysek.eu"):
    return render_template('debug_overview.html', domain=domain)

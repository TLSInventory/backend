from flask import Blueprint
bp = Blueprint('otherRoutes', __name__)

from flask import render_template


@bp.route('/')
def site_base_url():
    return "This endpoint should be used only for URL crafting, not actually retrieved."


@bp.route('/dashboard')
def dashboard_index():
    return render_template('index.html', title='Dashboard', test_arg=[])


@bp.route('/debug/html/batch_direct_scan')
def debug_batch_direct_scan_html():
    return render_template('debug_html/batch_direct_scan.html')


@bp.route('/debug/<string:domain>')
@bp.route('/debug/')
def debug_overview(domain="borysek.eu"):
    return render_template('debug_overview.html', domain=domain)

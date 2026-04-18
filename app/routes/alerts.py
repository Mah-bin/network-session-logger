from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from sqlalchemy import func
from app import db
from app.models import Alert, Device
from datetime import datetime, timedelta

alerts_bp = Blueprint('alerts', __name__)


# ---------------------------------------------------------------
# GET /alerts  -- all alerts with filters
# Query params: severity, resolved, device_ip, page
# ---------------------------------------------------------------
@alerts_bp.route('/alerts')
@login_required
def index():
    page       = request.args.get('page', 1, type=int)
    severity   = request.args.get('severity', '').strip()
    resolved   = request.args.get('resolved', 'false').strip()
    device_ip  = request.args.get('device_ip', '').strip()

    query = Alert.query.join(Device, Alert.device_id == Device.id)

    # Filter by severity
    if severity:
        query = query.filter(Alert.severity == severity)

    # Filter by resolved status
    if resolved == 'true':
        query = query.filter(Alert.is_resolved == True)
    else:
        query = query.filter(Alert.is_resolved == False)

    # Filter by device IP
    if device_ip:
        query = query.filter(Device.ip_address.like(f'%{device_ip}%'))

    alerts = query.order_by(Alert.timestamp.desc()).paginate(page=page, per_page=50, error_out=False)

    # Severity counts for summary bar
    severity_counts = (
        db.session.query(
            Alert.severity,
            func.count(Alert.id).label('count')
        )
        .filter(Alert.is_resolved == False)
        .group_by(Alert.severity)
        .all()
    )
    counts = {row.severity: row.count for row in severity_counts}

    return render_template(
        'alerts.html',
        alerts=alerts,
        severity_counts=counts,
        filters={'severity': severity, 'resolved': resolved, 'device_ip': device_ip},
    )


# ---------------------------------------------------------------
# POST /alerts/<id>/resolve  -- mark an alert as resolved
# ---------------------------------------------------------------
@alerts_bp.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
@login_required
def resolve(alert_id):
    if not current_user.is_analyst():
        flash('You do not have permission to resolve alerts.', 'danger')
        return redirect(url_for('alerts.index'))

    alert = Alert.query.get_or_404(alert_id)
    alert.is_resolved = True
    db.session.commit()

    flash(f'Alert #{alert_id} marked as resolved.', 'success')
    return redirect(url_for('alerts.index'))


# ---------------------------------------------------------------
# POST /alerts/resolve-all  -- resolve all open alerts (admin only)
# ---------------------------------------------------------------
@alerts_bp.route('/alerts/resolve-all', methods=['POST'])
@login_required
def resolve_all():
    if not current_user.is_admin():
        flash('Only admins can resolve all alerts at once.', 'danger')
        return redirect(url_for('alerts.index'))

    Alert.query.filter_by(is_resolved=False).update({'is_resolved': True})
    db.session.commit()

    flash('All open alerts have been resolved.', 'success')
    return redirect(url_for('alerts.index'))


# ---------------------------------------------------------------
# GET /api/alerts  -- open alerts as JSON (for dashboard widget)
# ---------------------------------------------------------------
@alerts_bp.route('/api/alerts')
@login_required
def api_alerts():
    limit = request.args.get('limit', 10, type=int)
    alerts = (
        Alert.query
        .filter_by(is_resolved=False)
        .order_by(Alert.timestamp.desc())
        .limit(limit)
        .all()
    )
    return jsonify([a.to_dict() for a in alerts])


# ---------------------------------------------------------------
# GET /api/alerts/summary  -- alert counts by severity as JSON
# ---------------------------------------------------------------
@alerts_bp.route('/api/alerts/summary')
@login_required
def summary():
    # Count of unresolved alerts by severity
    by_severity = (
        db.session.query(
            Alert.severity,
            func.count(Alert.id).label('count')
        )
        .filter(Alert.is_resolved == False)
        .group_by(Alert.severity)
        .all()
    )

    # Top 5 devices with the most unresolved alerts
    top_offenders = (
        db.session.query(
            Device.ip_address,
            func.count(Alert.id).label('alert_count')
        )
        .join(Alert, Alert.device_id == Device.id)
        .filter(Alert.is_resolved == False)
        .group_by(Device.ip_address)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
        .all()
    )

    # Alert trend: last 24h vs previous 24h
    now = datetime.utcnow()
    last_24h = Alert.query.filter(Alert.timestamp >= now - timedelta(hours=24)).count()
    prev_24h = Alert.query.filter(
        Alert.timestamp >= now - timedelta(hours=48),
        Alert.timestamp < now - timedelta(hours=24)
    ).count()

    return jsonify({
        'by_severity':   [{'severity': r.severity, 'count': r.count} for r in by_severity],
        'top_offenders': [{'ip': r.ip_address, 'alerts': r.alert_count} for r in top_offenders],
        'trend':         {'last_24h': last_24h, 'prev_24h': prev_24h},
    })

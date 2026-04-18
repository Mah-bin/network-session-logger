from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from sqlalchemy import func
from app import db
from app.models import Device, Session, Alert, AccessRule
from datetime import datetime, timedelta

devices_bp = Blueprint('devices', __name__)


# ---------------------------------------------------------------
# GET /devices  -- full device registry table
# ---------------------------------------------------------------
@devices_bp.route('/devices')
@login_required
def index():
    subnet = request.args.get('subnet', '').strip()

    query = Device.query
    if subnet:
        query = query.filter(Device.ip_address.like(f'{subnet}%'))

    local_devices = query.filter_by(device_type='local').order_by(Device.last_seen.desc()).all()
    external_devices = query.filter_by(device_type='external').order_by(Device.last_seen.desc()).all()

    return render_template('devices.html',
        local_devices=local_devices,
        external_devices=external_devices,
        subnet=subnet,
        now=datetime.now()
    )


# ---------------------------------------------------------------
# GET /devices/<id>  -- per-device detail and session history
# ---------------------------------------------------------------
@devices_bp.route('/devices/<int:device_id>')
@login_required
def detail(device_id):
    device = Device.query.get_or_404(device_id)

    # Last 50 sessions where this device was the source
    sessions = (
        Session.query
        .filter_by(src_device_id=device_id)
        .order_by(Session.timestamp.desc())
        .limit(50)
        .all()
    )

    # All alerts for this device
    alerts = (
        Alert.query
        .filter_by(device_id=device_id)
        .order_by(Alert.timestamp.desc())
        .all()
    )

    # Top destination IPs this device talked to
    top_destinations = (
        db.session.query(
            Device.ip_address,
            func.count(Session.id).label('count')
        )
        .join(Session, Session.dst_device_id == Device.id)
        .filter(Session.src_device_id == device_id)
        .group_by(Device.ip_address)
        .order_by(func.count(Session.id).desc())
        .limit(5)
        .all()
    )

    # Most used destination ports by this device
    top_ports = (
        db.session.query(
            Session.dst_port,
            func.count(Session.id).label('count')
        )
        .filter(Session.src_device_id == device_id)
        .group_by(Session.dst_port)
        .order_by(func.count(Session.id).desc())
        .limit(5)
        .all()
    )

    # Access rule history for this device
    access_rules = (
        AccessRule.query
        .filter_by(device_id=device_id)
        .order_by(AccessRule.created_at.desc())
        .all()
    )

    return render_template(
        'device_detail.html',
        device=device,
        sessions=sessions,
        alerts=alerts,
        top_destinations=top_destinations,
        top_ports=top_ports,
        access_rules=access_rules,
    )


# ---------------------------------------------------------------
# POST /devices/<id>/whitelist  -- whitelist a device (admin only)
# ---------------------------------------------------------------
@devices_bp.route('/devices/<int:device_id>/whitelist', methods=['POST'])
@login_required
def whitelist(device_id):
    if not current_user.is_analyst():
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('devices.detail', device_id=device_id))

    device = Device.query.get_or_404(device_id)
    reason = request.form.get('reason', '').strip() or 'No reason provided'

    device.is_whitelisted = True
    device.is_blacklisted = False
    device.risk_score     = 0

    rule = AccessRule(
        device_id=device_id,
        rule_type='whitelist',
        reason=reason,
        created_by=current_user.id
    )
    db.session.add(rule)
    db.session.commit()

    flash(f'{device.ip_address} has been whitelisted.', 'success')
    return redirect(url_for('devices.detail', device_id=device_id))


# ---------------------------------------------------------------
# POST /devices/<id>/blacklist  -- blacklist a device (admin only)
# ---------------------------------------------------------------
@devices_bp.route('/devices/<int:device_id>/blacklist', methods=['POST'])
@login_required
def blacklist(device_id):
    if not current_user.is_analyst():
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('devices.detail', device_id=device_id))

    device = Device.query.get_or_404(device_id)
    reason = request.form.get('reason', '').strip() or 'No reason provided'

    device.is_blacklisted = True
    device.is_whitelisted = False

    rule = AccessRule(
        device_id=device_id,
        rule_type='blacklist',
        reason=reason,
        created_by=current_user.id
    )
    db.session.add(rule)
    db.session.commit()

    flash(f'{device.ip_address} has been blacklisted.', 'danger')
    return redirect(url_for('devices.detail', device_id=device_id))


# ---------------------------------------------------------------
# POST /devices/<id>/remove-rule  -- remove whitelist/blacklist
# ---------------------------------------------------------------
@devices_bp.route('/devices/<int:device_id>/remove-rule', methods=['POST'])
@login_required
def remove_rule(device_id):
    if not current_user.is_admin():
        flash('Only admins can remove access rules.', 'danger')
        return redirect(url_for('devices.detail', device_id=device_id))

    device = Device.query.get_or_404(device_id)
    device.is_whitelisted = False
    device.is_blacklisted = False
    db.session.commit()

    flash(f'Access rules cleared for {device.ip_address}.', 'info')
    return redirect(url_for('devices.detail', device_id=device_id))


# ---------------------------------------------------------------
# GET /api/devices  -- all devices as JSON (for live updates)
# ---------------------------------------------------------------
@devices_bp.route('/api/devices')
@login_required
def api_devices():
    devices = Device.query.order_by(Device.last_seen.desc()).all()
    return jsonify([d.to_dict() for d in devices])

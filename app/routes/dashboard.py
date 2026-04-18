from flask import Blueprint, render_template, jsonify
from flask_login import login_required
from sqlalchemy import func
from app import db
from app.models import Device, Session, Alert
from datetime import datetime, timedelta

dashboard_bp = Blueprint('dashboard', __name__)


# ---------------------------------------------------------------
# GET /  -- main live dashboard page
# ---------------------------------------------------------------
@dashboard_bp.route('/')
@login_required
def index():
    # Summary counts for stat cards
    total_devices  = Device.query.count()
    total_sessions = Session.query.count()
    open_alerts    = Alert.query.filter_by(is_resolved=False).count()
    blacklisted    = Device.query.filter_by(is_blacklisted=True).count()

    # Last 20 sessions for initial table load (SocketIO updates after)
    recent_sessions = (
        Session.query
        .order_by(Session.timestamp.desc())
        .limit(20)
        .all()
    )

    # Unresolved critical/high alerts for sidebar
    urgent_alerts = (
        Alert.query
        .filter(Alert.is_resolved == False)
        .filter(Alert.severity.in_(['critical', 'high']))
        .order_by(Alert.timestamp.desc())
        .limit(5)
        .all()
    )

    return render_template(
        'dashboard.html',
        total_devices=total_devices,
        total_sessions=total_sessions,
        open_alerts=open_alerts,
        blacklisted=blacklisted,
        recent_sessions=recent_sessions,
        urgent_alerts=urgent_alerts,
    )


# ---------------------------------------------------------------
# GET /api/stats  -- JSON stats for live chart updates
# Called by dashboard.js via polling / SocketIO
# ---------------------------------------------------------------
@dashboard_bp.route('/api/stats')
@login_required
def stats():
    # Protocol breakdown for pie chart
    protocol_data = (
        db.session.query(
            Session.protocol,
            func.count(Session.id).label('count')
        )
        .group_by(Session.protocol)
        .all()
    )

    # Sessions per minute for the last 30 minutes (line chart
    thirty_mins_ago = datetime.now() - timedelta(minutes=30)
    hourly_data = (
        db.session.query(
            func.date_format(Session.timestamp, '%H:%i').label('hour'),
            func.count(Session.id).label('count')
        )
        .filter(Session.timestamp >= thirty_mins_ago)
        .group_by(func.date_format(Session.timestamp, '%H:%i'))
        .order_by('hour')
        .all()
    )

    # Top 5 source IPs by session count
    top_talkers = (
        db.session.query(
            Device.ip_address,
            func.count(Session.id).label('session_count')
        )
        .join(Session, Session.src_device_id == Device.id)
        .group_by(Device.ip_address)
        .order_by(func.count(Session.id).desc())
        .limit(5)
        .all()
    )

    return jsonify({
        'protocol_breakdown': [
            {'protocol': row.protocol or 'Unknown', 'count': row.count}
            for row in protocol_data
        ],
        'hourly_sessions': [
            {'hour': row.hour, 'count': row.count}
            for row in hourly_data
        ],
        'top_talkers': [
            {'ip': row.ip_address, 'sessions': row.session_count}
            for row in top_talkers
        ],
        'summary': {
            'total_devices':  Device.query.count(),
            'total_sessions': Session.query.count(),
            'open_alerts':    Alert.query.filter_by(is_resolved=False).count(),
            'blacklisted':    Device.query.filter_by(is_blacklisted=True).count(),
        }
    })


# ---------------------------------------------------------------
# GET /api/recent-sessions  -- last 20 sessions as JSON
# Polled by dashboard.js to refresh the live session table
# ---------------------------------------------------------------
@dashboard_bp.route('/api/recent-sessions')
@login_required
def recent_sessions():
    sessions = (
        Session.query
        .order_by(Session.timestamp.desc())
        .limit(20)  
        .all()
    )
    return jsonify([s.to_dict() for s in sessions])

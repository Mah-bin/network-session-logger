from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
from sqlalchemy import func, or_
from app import db
from app.models import Session, Device
from datetime import datetime, timedelta

sessions_bp = Blueprint('sessions', __name__)


# ---------------------------------------------------------------
# GET /sessions  -- full session log with filters
# Query params: ip, protocol, flag, from_date, to_date, page
# ---------------------------------------------------------------
@sessions_bp.route('/sessions')
@login_required
def index():
    page      = request.args.get('page', 1, type=int)
    ip        = request.args.get('ip', '').strip()
    protocol  = request.args.get('protocol', '').strip()
    flag      = request.args.get('flag', '').strip()
    from_date = request.args.get('from_date', '').strip()
    to_date   = request.args.get('to_date', '').strip()

    # Base query with joins to get IP addresses
    query = (
        Session.query
        .join(Device, Session.src_device_id == Device.id, isouter=True)
    )

    # Filter by IP (src or dst)
    if ip:
        src_match = Device.ip_address.like(f'%{ip}%')
        dst_devices = Device.query.filter(Device.ip_address.like(f'%{ip}%')).all()
        dst_ids = [d.id for d in dst_devices]
        query = query.filter(
            or_(src_match, Session.dst_device_id.in_(dst_ids))
        )

    # Filter by protocol
    if protocol:
        query = query.filter(Session.protocol == protocol.upper())

    # Filter by flag
    if flag:
        query = query.filter(Session.flag == flag)

    # Filter by date range
    if from_date:
        try:
            query = query.filter(Session.timestamp >= datetime.strptime(from_date, '%Y-%m-%d'))
        except ValueError:
            pass

    if to_date:
        try:
            to_dt = datetime.strptime(to_date, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(Session.timestamp <= to_dt)
        except ValueError:
            pass

    # Paginate results, 50 per page
    sessions = query.order_by(Session.timestamp.desc()).paginate(page=page, per_page=50, error_out=False)

    # Unique protocols for filter dropdown
    protocols = [
        row[0] for row in
        db.session.query(Session.protocol).distinct().all()
        if row[0]
    ]

    return render_template(
        'sessions.html',
        sessions=sessions,
        protocols=protocols,
        filters={'ip': ip, 'protocol': protocol, 'flag': flag, 'from_date': from_date, 'to_date': to_date},
    )


# ---------------------------------------------------------------
# GET /api/sessions  -- last N sessions as JSON
# Used by SocketIO and dashboard polling
# ---------------------------------------------------------------
@sessions_bp.route('/api/sessions')
@login_required
def api_sessions():
    limit = request.args.get('limit', 20, type=int)
    sessions = (
        Session.query
        .order_by(Session.timestamp.desc())
        .limit(limit)
        .all()
    )
    return jsonify([s.to_dict() for s in sessions])


# ---------------------------------------------------------------
# GET /api/sessions/summary  -- aggregated stats as JSON
# Protocol counts, flag breakdown, busiest ports
# ---------------------------------------------------------------
@sessions_bp.route('/api/sessions/summary')
@login_required
def summary():
    # Sessions by protocol
    by_protocol = (
        db.session.query(
            Session.protocol,
            func.count(Session.id).label('count')
        )
        .group_by(Session.protocol)
        .all()
    )

    # Sessions by flag (normal / suspicious / blocked)
    by_flag = (
        db.session.query(
            Session.flag,
            func.count(Session.id).label('count')
        )
        .group_by(Session.flag)
        .all()
    )

    # Top 10 busiest destination ports
    top_ports = (
        db.session.query(
            Session.dst_port,
            func.count(Session.id).label('count')
        )
        .filter(Session.dst_port.isnot(None))
        .group_by(Session.dst_port)
        .order_by(func.count(Session.id).desc())
        .limit(10)
        .all()
    )

    # Sessions in last 24 hours vs previous 24 hours (trend)
    now = datetime.utcnow()
    last_24h  = Session.query.filter(Session.timestamp >= now - timedelta(hours=24)).count()
    prev_24h  = Session.query.filter(
        Session.timestamp >= now - timedelta(hours=48),
        Session.timestamp < now - timedelta(hours=24)
    ).count()

    return jsonify({
        'by_protocol': [{'protocol': r.protocol or 'Unknown', 'count': r.count} for r in by_protocol],
        'by_flag':     [{'flag': r.flag or 'unknown', 'count': r.count} for r in by_flag],
        'top_ports':   [{'port': r.dst_port, 'count': r.count} for r in top_ports],
        'trend':       {'last_24h': last_24h, 'prev_24h': prev_24h},
    })

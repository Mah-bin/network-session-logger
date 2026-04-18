from app import db
from app.models import Device, Session, Alert
from datetime import datetime, timedelta
from sqlalchemy import func


# ---------------------------------------------------------------
# run_checks
# Entry point. Called after every session is logged.
# Runs all detection rules against the source device.
# Raises alerts and updates risk score if anomalies found.
# ---------------------------------------------------------------
def run_checks(app, device_id, port_scan_threshold, high_freq_threshold):
    with app.app_context():
        device = Device.query.get(device_id)
        if not device:
            return

        # Skip checks for whitelisted devices
        if device.is_whitelisted:
            return

        _check_port_scan(device, port_scan_threshold)
        _check_high_frequency(device, high_freq_threshold)
        _check_blacklisted_activity(device)

        db.session.commit()


# ---------------------------------------------------------------
# _check_port_scan
# Flags a device if it hits too many unique destination ports
# within the last 60 seconds. Classic port scan indicator.
# ---------------------------------------------------------------
def _check_port_scan(device, threshold):
    since = datetime.now() - timedelta(seconds=60)

    unique_ports = (
        db.session.query(func.count(func.distinct(Session.dst_port)))
        .filter(
            Session.src_device_id == device.id,
            Session.timestamp >= since,
            Session.dst_port.isnot(None)
        )
        .scalar()
    )

    if unique_ports >= threshold:
        # Only raise a new alert if no unresolved port_scan alert exists
        # for this device in the last 5 minutes (prevents alert flooding)
        recent = Alert.query.filter(
            Alert.device_id  == device.id,
            Alert.alert_type == 'port_scan',
            Alert.is_resolved == False,
            Alert.timestamp  >= datetime.now() - timedelta(minutes=5)
        ).first()

        if not recent:
            alert = Alert(
                device_id   = device.id,
                alert_type  = 'port_scan',
                description = (
                    f'{device.ip_address} hit {unique_ports} unique destination ports '
                    f'within 60 seconds. Possible port scan in progress.'
                ),
                severity    = 'high',
            )
            db.session.add(alert)
            _increment_risk(device, 20)

            # Flag the recent sessions from this device as suspicious
            Session.query.filter(
                Session.src_device_id == device.id,
                Session.timestamp >= since
            ).update({'flag': 'suspicious'})


# ---------------------------------------------------------------
# _check_high_frequency
# Flags a device if it generates too many sessions in 60 seconds.
# Could indicate a DDoS source, beaconing C2, or network flood.
# ---------------------------------------------------------------
def _check_high_frequency(device, threshold):
    since = datetime.now() - timedelta(seconds=60)

    session_count = (
        Session.query
        .filter(
            Session.src_device_id == device.id,
            Session.timestamp >= since
        )
        .count()
    )

    if session_count >= threshold:
        recent = Alert.query.filter(
            Alert.device_id  == device.id,
            Alert.alert_type == 'high_frequency',
            Alert.is_resolved == False,
            Alert.timestamp  >= datetime.now() - timedelta(minutes=5)
        ).first()

        if not recent:
            alert = Alert(
                device_id   = device.id,
                alert_type  = 'high_frequency',
                description = (
                    f'{device.ip_address} generated {session_count} sessions '
                    f'within 60 seconds. Possible flood or beaconing behavior.'
                ),
                severity    = 'high',
            )
            db.session.add(alert)
            _increment_risk(device, 15)


# ---------------------------------------------------------------
# _check_blacklisted_activity
# Any session from a blacklisted device is flagged as critical.
# Sessions are marked as blocked.
# ---------------------------------------------------------------
def _check_blacklisted_activity(device):
    if not device.is_blacklisted:
        return

    # Check if a critical blacklist alert was already raised recently
    recent = Alert.query.filter(
        Alert.device_id  == device.id,
        Alert.alert_type == 'blacklisted_device',
        Alert.is_resolved == False,
        Alert.timestamp  >= datetime.now() - timedelta(minutes=2)
    ).first()

    if not recent:
        alert = Alert(
            device_id   = device.id,
            alert_type  = 'blacklisted_device',
            description = (
                f'Traffic detected from blacklisted device {device.ip_address}. '
                f'This device has been flagged by an administrator.'
            ),
            severity    = 'critical',
        )
        db.session.add(alert)
        _increment_risk(device, 30)

    # Mark most recent session from this device as blocked
    latest_session = (
        Session.query
        .filter_by(src_device_id=device.id)
        .order_by(Session.timestamp.desc())
        .first()
    )
    if latest_session:
        latest_session.flag = 'blocked'


# ---------------------------------------------------------------
# _check_new_device
# Called separately when a brand new device is first seen.
# Raises a low severity alert so admins are notified.
# ---------------------------------------------------------------
def check_new_device(app, device_id):
    with app.app_context():
        device = Device.query.get(device_id)
        if not device:
            return

        alert = Alert(
            device_id   = device.id,
            alert_type  = 'new_device',
            description = (
                f'New device discovered on the network: {device.ip_address} '
                f'(MAC: {device.mac_address or "Unknown"}). '
                f'Please verify this device is authorized.'
            ),
            severity    = 'low',
        )
        db.session.add(alert)
        db.session.commit()


# ---------------------------------------------------------------
# _increment_risk
# Increases a device's risk score, capped at 100.
# ---------------------------------------------------------------
def _increment_risk(device, amount):
    device.risk_score = min(100, (device.risk_score or 0) + amount)

# app/sniffer/anomaly.py

def decay_risk_scores(app):
    """
    Periodically called to reduce risk scores of all devices.
    Prevents temporary spikes from causing permanent 'Critical' status.
    """
    with app.app_context():
        # Find all devices with a risk score > 0
        devices = Device.query.filter(Device.risk_score > 0).all()
        
        for device in devices:
            # Reduce by 5 points (or make this a setting in .env)
            # Ensure it never goes below 0
            decay_amount = 5 
            device.risk_score = max(0, device.risk_score - decay_amount)
            
        db.session.commit()
        if devices:
            print(f"[Anomaly Engine] Risk decay applied to {len(devices)} devices.")
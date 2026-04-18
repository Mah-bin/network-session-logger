import threading
import time
from datetime import datetime
from scapy.all import sniff
from app import db, socketio
from app.models import Device, Session
from app.sniffer.anomaly import run_checks, check_new_device, decay_risk_scores
from app.sniffer.parser import parse_packet, resolve_hostname, get_vendor, is_local_ip

# Local memory cache to store { ip_address: device_id }
# This prevents race conditions and redundant DB queries
DEVICE_CACHE = {}

# ---------------------------------------------------------------
# start_sniffer
# Public entry point. Called from run.py on app startup.
# ---------------------------------------------------------------
def start_sniffer(app):
    interface = app.config.get('NETWORK_INTERFACE', 'eth0')
    port_scan_threshold = app.config.get('PORT_SCAN_THRESHOLD', 20)
    high_freq_threshold = app.config.get('HIGH_FREQ_THRESHOLD', 100)

    # 1. Start the Sniffer Thread
    sniff_thread = threading.Thread(
        target=_sniff_loop,
        args=(app, interface, port_scan_threshold, high_freq_threshold),
        daemon=True,
        name='scapy-sniffer'
    )
    sniff_thread.start()

    # 2. Start the Risk Decay Thread (Runs every 5 minutes)
    decay_thread = threading.Thread(
        target=_decay_loop,
        args=(app,),
        daemon=True,
        name='risk-decay'
    )
    decay_thread.start()

    print(f'[Sniffer] System online. Interface: {interface} | Decay monitor: active')


def _decay_loop(app):
    """Background loop that periodically calls the decay logic in anomaly.py"""
    while True:
        # Wait 5 minutes between decay cycles
        time.sleep(300) 
        try:
            decay_risk_scores(app)
        except Exception as e:
            print(f'[Decay Error] {e}')


def _sniff_loop(app, interface, port_scan_threshold, high_freq_threshold):
    def handle(packet):
        _process_packet(packet, app, port_scan_threshold, high_freq_threshold)

    sniff(
        iface=interface,
        # Updated filter: captures all IP traffic EXCEPT traffic on port 5000
        filter='ip and not port 5000',
        prn=handle,
        store=False
    )

def _process_packet(packet, app, port_scan_threshold, high_freq_threshold):
    parsed = parse_packet(packet)
    if not parsed:
        return

    with app.app_context():
        try:
            # We now pass 'app' into _upsert_device
            src_device = _upsert_device(parsed['src_ip'], app, parsed['src_mac'])
            dst_device = _upsert_device(parsed['dst_ip'], app, parsed['dst_mac'])

            # Log the session
            session = Session(
                src_device_id = src_device.id if src_device else None,
                dst_device_id = dst_device.id if dst_device else None,
                src_port      = parsed['src_port'],
                dst_port      = parsed['dst_port'],
                protocol      = parsed['protocol'],
                packet_size   = parsed['packet_size'],
                timestamp     = datetime.now(),
                flag          = 'normal',
            )
            db.session.add(session)
            db.session.commit()

            # Push the new session to the live dashboard via SocketIO
            socketio.emit('new_session', session.to_dict())

            # Run anomaly detection on source device
            if src_device:
                run_checks(
                    app, 
                    src_device.id, 
                    port_scan_threshold, 
                    high_freq_threshold
                )

        except Exception as e:
            db.session.rollback()
            print(f'[Sniffer] Error processing packet: {e}')

def get_subnet(ip):
    parts = ip.split('.')
    return '.'.join(parts[:3]) if len(parts) == 4 else None

def _upsert_device(ip, app, mac=None):
    if not ip:
        return None

    # Check local memory cache first to avoid DB hits
    if ip in DEVICE_CACHE:
        return Device.query.get(DEVICE_CACHE[ip])

    device = Device.query.filter_by(ip_address=ip).first()
    is_new = device is None

    if is_new:
        device = Device(
            ip_address  = ip,
            mac_address = mac,
            hostname    = resolve_hostname(ip),
            vendor      = get_vendor(mac),
            first_seen  = datetime.now(),
            last_seen   = datetime.now(),
            device_type = 'local' if is_local_ip(ip) else 'external',
            network     = get_subnet(ip)
        )
        db.session.add(device)
        db.session.flush() 
        print(f'[Sniffer] New device discovered: {ip}')
    else:
        # Update existing device
        device.last_seen = datetime.now()
        if mac and not device.mac_address:
            device.mac_address = mac
            device.vendor = get_vendor(mac)

    db.session.commit()
    
    # Update local cache with the ID
    DEVICE_CACHE[ip] = device.id

    # Raise a new_device alert
    if is_new:
        # Using the 'app' passed from start_sniffer/_process_packet
        threading.Thread(
            target=check_new_device,
            args=(app, device.id),
            daemon=True
        ).start()

    return device
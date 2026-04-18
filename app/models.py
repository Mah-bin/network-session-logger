from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


# ============================================================
# User loader for Flask-Login
# ============================================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ============================================================
# Device
# Every unique IP/MAC seen on the network gets one row here.
# All sessions and alerts reference this table.
# ============================================================
class Device(db.Model):
    __tablename__ = 'devices'

    id             = db.Column(db.Integer, primary_key=True)
    ip_address     = db.Column(db.String(45), unique=True, nullable=False, index=True)
    mac_address    = db.Column(db.String(17))
    hostname       = db.Column(db.String(255))
    vendor         = db.Column(db.String(255))
    first_seen     = db.Column(db.DateTime, default=datetime.now)
    last_seen      = db.Column(db.DateTime, default=datetime.now)
    is_whitelisted = db.Column(db.Boolean, default=False)
    is_blacklisted = db.Column(db.Boolean, default=False)
    risk_score     = db.Column(db.Integer, default=0)
    device_type    = db.Column(db.String(10), default='external')
    device_type = db.Column(db.String(10), default='external')
    network     = db.Column(db.String(20), default=None)

    # Relationships
    src_sessions = db.relationship(
        'Session',
        foreign_keys='Session.src_device_id',
        backref='src_device',
        lazy='dynamic'
    )
    dst_sessions = db.relationship(
        'Session',
        foreign_keys='Session.dst_device_id',
        backref='dst_device',
        lazy='dynamic'
    )
    alerts = db.relationship('Alert', backref='device', lazy='dynamic')
    access_rules = db.relationship('AccessRule', backref='device', lazy='dynamic')

    def to_dict(self):
        return {
            'id':             self.id,
            'ip_address':     self.ip_address,
            'mac_address':    self.mac_address or 'N/A',
            'hostname':       self.hostname or 'Unknown',
            'vendor':         self.vendor or 'Unknown',
            'first_seen':     self.first_seen.strftime('%Y-%m-%d %H:%M:%S') if self.first_seen else None,
            'last_seen':      self.last_seen.strftime('%Y-%m-%d %H:%M:%S') if self.last_seen else None,
            'is_whitelisted': self.is_whitelisted,
            'is_blacklisted': self.is_blacklisted,
            'risk_score':     self.risk_score,
            'device_type':    self.device_type,
        }

    def __repr__(self):
        return f'<Device {self.ip_address}>'


# ============================================================
# Session
# One row per captured network connection event.
# This will be the largest table in the database.
# ============================================================
class Session(db.Model):
    __tablename__ = 'sessions'

    id            = db.Column(db.Integer, primary_key=True)
    src_device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=True, index=True)
    dst_device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=True, index=True)
    src_port      = db.Column(db.Integer)
    dst_port      = db.Column(db.Integer)
    protocol      = db.Column(db.String(10))
    packet_size   = db.Column(db.Integer)
    timestamp     = db.Column(db.DateTime, default=datetime.now, index=True)
    duration      = db.Column(db.Float, default=0.0)
    flag          = db.Column(db.String(20), default='normal')   # normal | suspicious | blocked

    def to_dict(self):
        return {
            'id':          self.id,
            'src_ip':      self.src_device.ip_address if self.src_device else 'Unknown',
            'dst_ip':      self.dst_device.ip_address if self.dst_device else 'Unknown',
            'src_port':    self.src_port,
            'dst_port':    self.dst_port,
            'protocol':    self.protocol,
            'packet_size': self.packet_size,
            'timestamp':   self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else None,
            'duration':    self.duration,
            'flag':        self.flag,
        }

    def __repr__(self):
        return f'<Session {self.id} {self.protocol}>'


# ============================================================
# Alert
# Raised by the anomaly detection engine.
# Linked to the device that triggered the alert.
# ============================================================
class Alert(db.Model):
    __tablename__ = 'alerts'

    id          = db.Column(db.Integer, primary_key=True)
    device_id   = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False, index=True)
    alert_type  = db.Column(db.String(100))                         # e.g. port_scan, high_frequency
    description = db.Column(db.Text)
    severity    = db.Column(db.Enum('low', 'medium', 'high', 'critical'), default='medium')
    timestamp   = db.Column(db.DateTime, default=datetime.now, index=True)
    is_resolved = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id':          self.id,
            'ip_address':  self.device.ip_address if self.device else 'Unknown',
            'alert_type':  self.alert_type,
            'description': self.description,
            'severity':    self.severity,
            'timestamp':   self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else None,
            'is_resolved': self.is_resolved,
        }

    def __repr__(self):
        return f'<Alert {self.alert_type} on {self.device_id}>'


# ============================================================
# User
# Admin/analyst accounts for the web dashboard.
# Passwords stored as bcrypt hashes via werkzeug.
# ============================================================
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role          = db.Column(db.Enum('admin', 'analyst', 'viewer'), default='viewer')
    created_at    = db.Column(db.DateTime, default=datetime.now)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == 'admin'

    def is_analyst(self):
        return self.role in ('admin', 'analyst')

    def to_dict(self):
        return {
            'id':         self.id,
            'username':   self.username,
            'role':       self.role,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
        }

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


# ============================================================
# AccessRule
# Records every whitelist/blacklist decision by an admin.
# Provides an audit trail of who did what and why.
# ============================================================
class AccessRule(db.Model):
    __tablename__ = 'access_rules'

    id         = db.Column(db.Integer, primary_key=True)
    device_id  = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    rule_type  = db.Column(db.Enum('whitelist', 'blacklist'), nullable=False)
    reason     = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

    # Relationships
    admin = db.relationship('User', backref='access_rules')

    def to_dict(self):
        return {
            'id':         self.id,
            'device_ip':  self.device.ip_address if self.device else 'Unknown',
            'rule_type':  self.rule_type,
            'reason':     self.reason,
            'created_by': self.admin.username if self.admin else 'Unknown',
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
        }

    def __repr__(self):
        return f'<AccessRule {self.rule_type} on device {self.device_id}>'

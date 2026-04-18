from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_login import LoginManager
from config import Config

# ----------------------------
# Extension instances
# Initialised without app here, bound in create_app()
# ----------------------------
db = SQLAlchemy()
socketio = SocketIO()
login_manager = LoginManager()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # ----------------------------
    # Bind extensions to app
    # ----------------------------
    db.init_app(app)
    socketio.init_app(app, async_mode='threading', cors_allowed_origins='*')

    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'

    # ----------------------------
    # Register blueprints
    # ----------------------------
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.devices import devices_bp
    from app.routes.sessions import sessions_bp
    from app.routes.alerts import alerts_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(sessions_bp)
    app.register_blueprint(alerts_bp)

    # ----------------------------
    # Create all DB tables
    # ----------------------------
    with app.app_context():
        db.create_all()

    return app

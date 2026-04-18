import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # ----------------------------
    # Core Flask Config
    # ----------------------------
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

    # ----------------------------
    # MySQL Database
    # ----------------------------
    DB_USER     = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', 'messiwc2022')
    DB_HOST     = os.environ.get('DB_HOST', '127.0.0.1')  
    DB_PORT     = os.environ.get('DB_PORT', '3306')
    DB_NAME     = os.environ.get('DB_NAME', 'network_logger')

    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ----------------------------
    # Network Sniffer Config
    # ----------------------------
    NETWORK_INTERFACE = os.environ.get('NETWORK_INTERFACE', None)  

    # ----------------------------
    # Anomaly Detection Thresholds
    # ----------------------------
    PORT_SCAN_THRESHOLD = int(os.environ.get('PORT_SCAN_THRESHOLD', 20))
    HIGH_FREQ_THRESHOLD = int(os.environ.get('HIGH_FREQ_THRESHOLD', 100))
    RISK_SCORE_INCREMENT = int(os.environ.get('RISK_SCORE_INCREMENT', 10))
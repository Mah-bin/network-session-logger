from app import create_app, socketio
from app.sniffer.capture import start_sniffer

app = create_app()

if __name__ == '__main__':
    start_sniffer(app)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)

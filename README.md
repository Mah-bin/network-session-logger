# Network Session Logger

Network Session Logger is a Flask-based web application that captures network traffic using Scapy, analyzes it in real-time, and provides a dashboard for monitoring network sessions and potential anomalies. It features user authentication, a MySQL database for storing logs and user information, and real-time updates via WebSockets.

## Features

- **Network Sniffing**: Uses Scapy to capture and analyze network packets in real-time.
- **Anomaly Detection**: Identifies suspicious activities such as port scans and high-frequency requests.
- **Real-time Dashboard**: Live updates of network events using Flask-SocketIO.
- **User Authentication**: Secure login system with hashed passwords using Flask-Login and Flask-Bcrypt.
- **Persistent Storage**: Stores network logs and user data in a MySQL database.

## Prerequisites

- Python 3.x
- MySQL Server
- Npcap (on Windows) or libpcap (on Linux) for Scapy

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/Mah-bin/network-session-logger.git
   cd network-session-logger
   ```

2. **Set up a virtual environment (recommended):**

   ```bash
   python -m venv venv
   # On Windows
   venv\Scripts\activate
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Database Configuration:**

   - Ensure your MySQL server is running.
   - Create a database named `network_logger` (or your preferred name).
   - Configure the database credentials.

5. **Environment Variables:**

   Create a `.env` file in the root directory and add the following configurations (adjust as needed):

   ```env
   SECRET_KEY=your-secret-key
   DB_USER=root
   DB_PASSWORD=your-db-password
   DB_HOST=127.0.0.1
   DB_PORT=3306
   DB_NAME=network_logger
   NETWORK_INTERFACE=Your-Network-Interface-Name # Optional, defaults to all/default
   PORT_SCAN_THRESHOLD=20
   HIGH_FREQ_THRESHOLD=100
   RISK_SCORE_INCREMENT=10
   ```

## Usage

1. **Run the application:**

   You may need to run this with administrator/root privileges depending on your OS, as Scapy requires raw socket access to capture packets.

   ```bash
   python run.py
   ```

2. **Access the Dashboard:**

   Open your web browser and navigate to `http://localhost:5000`.

## Architecture

- **Flask**: The core web framework.
- **Flask-SQLAlchemy**: ORM for database interactions.
- **Flask-SocketIO**: For real-time bi-directional communication between the server and the web clients.
- **Scapy**: For low-level network packet manipulation and capture.
- **PyMySQL**: Python MySQL client library.

## Disclaimer

This tool is designed for educational and network monitoring purposes on networks you own or have explicit permission to monitor. Do not use this tool on unauthorized networks.

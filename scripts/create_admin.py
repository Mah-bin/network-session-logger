"""
Run this once to create your first admin account.
Usage: python scripts/create_admin.py
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app, db
from app.models import User

app = create_app()

with app.app_context():
    username = input("Enter admin username: ").strip()
    password = input("Enter admin password: ").strip()

    if User.query.filter_by(username=username).first():
        print(f"User '{username}' already exists.")
        sys.exit(1)

    admin = User(username=username, role='admin')
    admin.set_password(password)
    db.session.add(admin)
    db.session.commit()
    print(f"Admin user '{username}' created successfully.")

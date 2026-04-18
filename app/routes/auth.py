from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User

auth_bp = Blueprint('auth', __name__)


# ---------------------------------------------------------------
# GET  /login  -- show login form
# POST /login  -- validate credentials, start session
# ---------------------------------------------------------------
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash(f'Welcome back, {user.username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard.index'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


# ---------------------------------------------------------------
# GET /logout  -- end the user session
# ---------------------------------------------------------------
@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


# ---------------------------------------------------------------
# GET  /register  -- show registration form  (admin only)
# POST /register  -- create a new user
# ---------------------------------------------------------------
@auth_bp.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if not current_user.is_admin():
        flash('Only admins can create new accounts.', 'danger')
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role     = request.form.get('role', 'viewer').strip()

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('register.html')

        if role not in ('admin', 'analyst', 'viewer'):
            flash('Invalid role selected.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash(f"Username '{username}' is already taken.", 'danger')
            return render_template('register.html')

        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash(f"User '{username}' created successfully with role '{role}'.", 'success')
        return redirect(url_for('auth.register'))

    return render_template('register.html')

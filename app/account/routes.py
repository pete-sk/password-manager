import os
import base64
from io import BytesIO
from smtplib import SMTPRecipientsRefused
from flask import Blueprint, Markup, render_template, request, url_for, flash, redirect, send_file, session, abort
from flask_login import login_user, current_user, logout_user, login_required

from app import db, bcrypt
from app.models import User
from app.account.forms import PasswordPrompt
from app.account.forms import (RegistrationForm, LoginForm, UpdateAccountForm, RequestResetForm, ResetPasswordForm,
                               ChangeMasterKeyForm, Enable2FAForm, TFAForm)
from app.account.utils import send_activation_email, send_reset_email
from app.utils.generate_password import generate_pswrd
from app.utils.encryption import get_key, encrypt, decrypt
from app.user_data.utils import wipe_user_data, reencrypt_user_data, check_master_key

account = Blueprint('account', __name__)


@account.route('/account/register', methods=['GET', 'POST'])
def register():
    title = 'Create an account'

    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data.lower()
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        master_key = generate_pswrd(length=32, special=False)
        encrypted_master_key = encrypt(get_key(form.password.data), master_key)
        user = User(email=email, password=hashed_password, master_key=encrypted_master_key)

        try:
            send_activation_email(user)
            flash('Account created! Verification link has been sent to your email.', 'success')
        except SMTPRecipientsRefused:
            flash('Entered email address is invalid!', 'danger')
            return redirect(url_for('account.register'))
        except:
            user.activated = True
            flash('Account created! You can now log in.', 'success')

        db.session.add(user)
        db.session.commit()

        return redirect(url_for('account.login'))

    return render_template('account/register.html', title=title, form=form)


@account.route('/account/activate-account/resend-activation-link/<string:email>')
def resend_activation_link(email):
    user = User.query.filter_by(email=email).first()
    if user:
        send_activation_email(user)
        flash('Verification link has been sent to your email.', 'success')
    else:
        flash('Something went wrong. Try again.', 'danger')
    return redirect(url_for('account.login'))


@account.route('/account/activate-account/<token>')
def activate_account_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    verify = User.verify_activation_token(token)
    user = verify[0]
    email = verify[1]
    if not user or email != user.email:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('account.login'))
    user.activated = True
    db.session.commit()
    flash('Your email has been confirmed. You can now log in.', 'success')
    return redirect(url_for('account.login'))


@account.route('/account/login', methods=['GET', 'POST'])
def login():
    title = 'Login'

    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and bcrypt.check_password_hash(user.password.encode(), form.password.data):
            if user.activated != 0:
                session['email'] = user.email
                session['master_key'] = decrypt(get_key(form.password.data), user.master_key)
                if user.otp_secret is None:
                    login_user(user, remember=form.remember.data)
                    session['encryption_key'] = get_key(session['master_key'])
                    next_page = request.args.get('next')
                    return redirect(next_page) if next_page else redirect(url_for('main.index'))
                else:
                    return redirect(url_for('account.login_2fa'))
            else:
                flash(Markup(f'Your  email address is not confirmed. Check your email for the verification link or '
                      f'<a href="{url_for("account.resend_activation_link", email=user.email)}">'
                             f'send again.</a>'), 'warning')
        else:
            flash('Invalid email or password!', 'danger')

    return render_template('account/login.html', title=title, form=form)


@account.route('/account/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    title = 'Login'

    user = User.query.filter_by(email=session['email']).first()
    form = TFAForm()
    if form.validate_on_submit():
        if user.verify_totp(form.security_code.data):
            login_user(user, remember=form.remember.data)
            session['encryption_key'] = get_key(session['master_key'])
            return redirect(url_for('main.index'))
        else:
            session['email'] = None
            session['master_key'] = None
            flash('Invalid security code!', 'danger')
            return redirect(url_for('account.login'))

    return render_template('account/login_2fa.html', title=title, form=form)


@account.route('/account/logout')
def logout():
    logout_user()
    flash('Successfully logged out.', 'success')
    return redirect(url_for('main.index'))


@account.route('/download/master_key.txt')
@login_required
def download_master_key():
    return send_file(BytesIO(session['master_key'].encode('utf-8')),
                     attachment_filename='master_key.txt', as_attachment=True)


@account.route('/account/settings/change-master-key', methods=['GET', 'POST'])
@login_required
def change_master_key():
    title = 'Get a New Master Key'

    form = ChangeMasterKeyForm()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password.encode(), form.password.data):
            current_user.master_key = encrypt(get_key(form.password.data), form.master_key.data)

            old_encryption_key = session['encryption_key']
            new_encryption_key = get_key(form.master_key.data)
            reencrypt_user_data(current_user, old_encryption_key, new_encryption_key)
            db.session.commit()

            session['master_key'] = form.master_key.data
            session['encryption_key'] = new_encryption_key
            flash('Master key has been changed. Don\'t forget to save it in a secure place!', 'success')
            return redirect(url_for('account.account_settings'))
        else:
            flash('The password you entered is incorrect.', 'danger')
            return redirect(url_for('account.change_master_key'))
    elif request.method == 'GET':
        form.master_key.data = generate_pswrd(length=32, special=False)

    return render_template('account/change_master_key.html', title=title, form=form)


@account.route('/account/settings/2fa/setup', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    title = 'Enable Two Factor Authentication'

    if current_user.otp_secret is not None:
        return abort(403)

    form = Enable2FAForm()
    if form.validate_on_submit():
        password = form.password.data
        if bcrypt.check_password_hash(current_user.password.encode(), password):
            current_user.otp_secret = form.secret.data
            db.session.commit()
            flash('Two Factor Authentication has been enabled.', 'success')
            return redirect(url_for('account.account_settings'))
        else:
            flash('The password you entered is incorrect.', 'danger')
            flash('Two Factor Authentication has NOT been turned on. Please start again from scratch - '
                  'previous credentials have been discarded and will not work with this account.', 'warning')
            return redirect(url_for('account.account_settings'))
    else:
        secret = base64.b32encode(os.urandom(10)).decode('utf-8')
        form.secret.data = secret
        return render_template('account/2fa_setup.html', title=title, form=form, secret=secret), \
            {'Cache-Control': 'no-cache, no-store, must-revalidate',
             'Pragma': 'no-cache',
             'Expires': '0'}


@account.route('/account/settings/2fa/setup/otp-path/<secret>')
@login_required
def get_otp_path(secret):
    path = f'otpauth://totp/Password Manager:{current_user.email}?secret={secret}&issuer=Password Manager'
    return path


@account.route('/account/settings/2fa/disable', methods=['GET', 'POST'])
@login_required
def disable_2fa():
    title = 'Disable Two Factor Authentication'

    if current_user.otp_secret is None:
        return abort(403)

    form = PasswordPrompt()
    if form.validate_on_submit():
        password = form.password.data
        if bcrypt.check_password_hash(current_user.password.encode(), password):
            current_user.otp_secret = None
            db.session.commit()
            flash('Two Factor Authentication has been disabled.', 'success')
            return redirect(url_for('account.account_settings'))
        else:
            flash('The password you entered is incorrect.', 'danger')
            return redirect(url_for('account.account_settings'))
    else:
        return render_template('account/2fa_disable.html', title=title, form=form)


@account.route('/account/settings/delete-account', methods=['GET', 'POST'])
@login_required
def delete_account():
    title = 'Delete Account'

    form = PasswordPrompt()
    if form.validate_on_submit():
        password = form.password.data
        if bcrypt.check_password_hash(current_user.password.encode(), password):
            wipe_user_data(current_user)
            db.session.delete(current_user)
            db.session.commit()
            flash('Your account has been deleted.', 'success')
            return redirect(url_for('main.index'))
        else:
            flash('The password you entered is incorrect.', 'danger')
            return redirect(url_for('account.delete_account'))

    return render_template('account/delete_account.html', title=title, form=form)


@account.route('/account/settings', methods=['GET', 'POST'])
@login_required
def account_settings():
    title = 'Account Settings'

    # Check if 2fa is enabled for current user
    if current_user.otp_secret is None:
        tfa = False
    else:
        tfa = True

    form = UpdateAccountForm()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password.encode(), form.current_password.data):
            if form.email.data != current_user.email:
                current_user.email = form.email.data
                current_user.activated = False
                send_activation_email(current_user)
                flash('Email address has been changed. Please check your email for the verification link.', 'success')
            if form.new_password.data:
                current_user.password = bcrypt.generate_password_hash(form.new_password.data)
                current_user.master_key = encrypt(get_key(form.new_password.data), session['master_key'])
                flash('Password has been updated.', 'success')
            db.session.commit()
            return redirect(url_for('account.account_settings'))
    elif request.method == 'GET':
        form.email.data = current_user.email

    return render_template('account/account_settings.html', title=title, form=form, tfa=tfa)


@account.route('/account/reset-password', methods=['GET', 'POST'])
def reset_request():
    title = 'Reset Password'

    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        try:
            send_reset_email(user)
            flash('An email with the reset link has been sent.', 'success')
        except:
            flash('Cannot send a reset link at the moment. Please try again later.', 'danger')
        return redirect(url_for('account.login'))
    return render_template('account/password_reset_request.html', title=title, form=form)


@account.route('/account/reset-password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    title = 'Reset Password'

    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    user = User.verify_reset_token(token)
    if not user:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('account.reset_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():

        if bcrypt.check_password_hash(user.password.encode(), form.password.data):
            flash('The password you entered is already set.', 'danger')
            return redirect(url_for('account.reset_token', token=token))

        file_contents = ''
        if form.master_key_file.data:
            file_contents = form.master_key_file.data.stream.readline().decode('utf-8')

        if not form.master_key.data and not file_contents and form.lost_master_key.data:
            wipe_user_data(user)
            master_key = generate_pswrd(length=32, special=False)
            user.master_key = encrypt(get_key(form.password.data), master_key)
            flash('User data has been permanently erased! Master key has been reset.', 'warning')
        elif not check_master_key(form.master_key.data, user) and not check_master_key(file_contents, user):
            flash('Master key invalid or not provided!', 'danger')
            return redirect(url_for('account.reset_token', token=token))
        else:
            user.master_key = encrypt(get_key(form.password.data), form.master_key.data)

        user.password = bcrypt.generate_password_hash(form.password.data)
        db.session.commit()
        flash('Password has been updated.', 'success')
        return redirect(url_for('account.login'))

    return render_template('account/password_reset_token.html', title=title, form=form)

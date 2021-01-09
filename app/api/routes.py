from flask import Blueprint, jsonify, request

from app import bcrypt
from app.utils.nocache import nocache
from app.models import User
from app.user_data.utils import export_encrypted_user_data
from app.api.utils import process_user_data_manipulation_request

api = Blueprint('api', __name__)


@api.route('/api/get_token', methods=['GET', 'POST'])
def get_token():
    """Sends API token if valid credentials provided."""
    email = request.json['email']
    password = request.json['password']
    security_code = request.json['security_code']

    user = User.query.filter_by(email=email.lower()).first()
    if user:
        if user.otp_secret:
            if security_code:
                if bcrypt.check_password_hash(user.password.encode(), password) and user.verify_totp(security_code):
                    return user.get_api_token()
                else:
                    return 'invalid_credentials', 404
            else:
                return 'enter_security_code', 401
        else:
            if bcrypt.check_password_hash(user.password.encode(), password):
                return user.get_api_token()
            else:
                return 'invalid_credentials', 404
    return 'invalid_credentials', 404


@api.route('/api/get/<token>')
@nocache
def send_encrypted_user_data(token):
    user = User.verify_api_token(token)
    if user:
        return jsonify(export_encrypted_user_data(user, include_master_key=True))
    else:
        return '', 404


@api.route('/api/post/<token>', methods=['POST'])
def receive_user_data_manipulation_request(token):
    """Receive a dict of encrypted user data or deletion request."""
    # dict template: data = {'action': 'add/edit/delete', 'data_type': 'password/secure_note/credit_card', 'data': data}
    user = User.verify_api_token(token)
    if user == 'expired':
        return 'signature expired', 401
    elif user:
        if process_user_data_manipulation_request(request.json, user):
            return 'success', 200
        else:
            return 'failure', 500

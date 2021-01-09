from flask import Blueprint, render_template, url_for, redirect
from flask_login import current_user

main = Blueprint('main', __name__)


@main.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('user_data.access_all'))
    else:
        return redirect(url_for('main.about'))


@main.route('/about')
def about():
    return render_template('main/index.html')


@main.route('/generate-password', methods=['GET', 'POST'])
def generate_password():
    title = 'Generate Password'
    return render_template('main/generate_password.html', title=title)

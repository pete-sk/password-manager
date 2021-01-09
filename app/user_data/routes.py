from io import BytesIO
from flask import Blueprint, render_template, request, url_for, flash, redirect, abort, session, send_file
from flask_login import current_user, login_required

from app import db
from app.utils.nocache import nocache
from app.models import Password, SecureNote, CreditCard
from app.user_data.forms import SearchForm
from app.utils.encryption import encrypt
from app.user_data.forms import NewPasswordForm, NewSecureNoteForm, NewCreditCardForm, ImportDataForm
from app.user_data.utils import (get_user_passwords, get_user_secure_notes, get_user_credit_cards,
                                 search_passwords, search_secure_notes, search_credit_cards,
                                 encrypt_password, encrypt_secure_note, encrypt_credit_card,
                                 decrypt_password, decrypt_secure_note, decrypt_credit_card,
                                 export_encrypted_user_data, import_encrypted_user_data, save_imported_user_data)

user_data = Blueprint('user_data', __name__)


@user_data.route('/all', methods=['GET', 'POST'])
@login_required
def access_all():
    title = 'Saved Items'

    encryption_key = session['encryption_key']
    user_all = []
    user_passwords = get_user_passwords(current_user, encryption_key)
    user_secure_notes = get_user_secure_notes(current_user, encryption_key)
    user_credit_cards = get_user_credit_cards(current_user, encryption_key)

    search = False
    form = SearchForm()
    if form.validate_on_submit():
        query = form.query.data
        results = []
        results.extend(search_passwords(user_passwords, query))
        results.extend(search_secure_notes(user_secure_notes, query))
        results.extend(search_credit_cards(user_credit_cards, query))
        user_all = results
        search = True
    else:
        user_all.extend(user_passwords)
        user_all.extend(user_secure_notes)
        user_all.extend(user_credit_cards)

    user_all.sort(key=lambda entry: entry.name)

    return render_template('user_data/all.html', title=title, form=form, entries=user_all, search=search)


@user_data.route('/passwords', methods=['GET', 'POST'])
@login_required
def access_passwords():
    title = 'Saved Passwords'

    encryption_key = session['encryption_key']
    user_passwords = get_user_passwords(current_user, encryption_key)

    search = False
    form = SearchForm()
    if form.validate_on_submit():
        query = form.query.data
        user_passwords = search_passwords(user_passwords, query)
        search = True

    user_passwords.sort(key=lambda entry: entry.name)

    return render_template('user_data/passwords/passwords.html', title=title, form=form, entries=user_passwords,
                           search=search)


@user_data.route('/passwords/new', methods=['GET', 'POST'])
@login_required
def add_password():
    title = 'Add Password'

    encryption_key = session['encryption_key']
    form = NewPasswordForm()
    if form.validate_on_submit():
        name = form.name.data
        site = form.site.data
        if not name and site:
            name = site
        elif not name and not site:
            name = '(unnamed)'
        username = form.username.data
        password = form.password.data
        user = current_user
        entry = Password(name=name, site=site, username=username, password=password, user=user)
        entry = encrypt_password(encryption_key, entry)
        db.session.add(entry)
        db.session.commit()
        flash('Password has been saved.', 'success')
        return redirect(url_for('user_data.access_passwords'))

    return render_template('user_data/passwords/edit_password.html', title=title, form=form)


@user_data.route('/passwords/<int:entry_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_password(entry_id):
    title = 'Edit Entry'

    encryption_key = session['encryption_key']
    entry = Password.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        abort(403)
    form = NewPasswordForm()
    if form.validate_on_submit():
        entry.name = form.name.data
        entry.site = form.site.data
        if not entry.name and entry.site:
            entry.name = entry.site
        elif not entry.name and not entry.site:
            entry.name = '(unnamed)'
        entry.username = form.username.data
        entry.password = form.password.data
        entry = encrypt_password(encryption_key, entry)
        db.session.commit()
        flash('Entry has been updated.', 'success')
        return redirect(url_for('user_data.access_passwords'))
    elif request.method == 'GET':
        entry = decrypt_password(encryption_key, entry)
        form.name.data = entry.name
        form.site.data = entry.site
        form.username.data = entry.username
        form.password.data = entry.password

    return render_template('user_data/passwords/edit_password.html', title=title, form=form)


@user_data.route('/passwords/<int:entry_id>/delete', methods=['POST'])
@login_required
def delete_password(entry_id):
    entry = Password.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        abort(403)
    db.session.delete(entry)
    db.session.commit()
    # flash('Entry has been deleted.', 'success')

    return redirect(url_for('user_data.access_all'))


@user_data.route('/secure_notes', methods=['GET', 'POST'])
@login_required
def access_secure_notes():
    title = 'Saved Secure Notes'

    encryption_key = session['encryption_key']
    user_secure_notes = get_user_secure_notes(current_user, encryption_key)
    user_secure_notes.sort(key=lambda entry: entry.name)

    search = False
    form = SearchForm()
    if form.validate_on_submit():
        query = form.query.data
        user_secure_notes = search_secure_notes(user_secure_notes, query)
        search = True

    user_secure_notes.sort(key=lambda entry: entry.name)

    return render_template('user_data/secure_notes/secure_notes.html', title=title, form=form, entries=user_secure_notes,
                           search=search)


@user_data.route('/secure_notes/new', methods=['GET', 'POST'])
@login_required
def add_secure_note():
    title = 'Add Secure Note'

    encryption_key = session['encryption_key']
    form = NewSecureNoteForm()
    if form.validate_on_submit():
        name = form.name.data
        if not name:
            name = '(unnamed)'
        name = encrypt(encryption_key, name)
        content = encrypt(encryption_key, form.content.data)
        user = current_user
        entry = SecureNote(name=name, content=content, user=user)
        db.session.add(entry)
        db.session.commit()
        flash('Secure Note has been saved.', 'success')
        return redirect(url_for('user_data.access_secure_notes'))

    return render_template('user_data/secure_notes/edit_secure_note.html', title=title, form=form)


@user_data.route('/secure_notes/<int:entry_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_secure_note(entry_id):
    title = 'Edit Secure Note'

    encryption_key = session['encryption_key']
    entry = SecureNote.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        abort(403)
    form = NewSecureNoteForm()
    if form.validate_on_submit():
        entry.name = form.name.data
        if not entry.name:
            entry.name = '(unnamed)'
        entry.content = form.content.data
        entry = encrypt_secure_note(encryption_key, entry)
        db.session.commit()
        flash('Secure note has been updated.', 'success')
        return redirect(url_for('user_data.access_secure_notes'))
    elif request.method == 'GET':
        entry = decrypt_secure_note(encryption_key, entry)
        form.name.data = entry.name
        form.content.data = entry.content

    return render_template('user_data/secure_notes/edit_secure_note.html', title=title, form=form)


@user_data.route('/secure_notes/<int:entry_id>/delete', methods=['POST'])
@login_required
def delete_secure_note(entry_id):
    entry = SecureNote.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        abort(403)
    db.session.delete(entry)
    db.session.commit()
    # flash('Secure note has been deleted.', 'success')

    return redirect(url_for('user_data.access_all'))


@user_data.route('/credit_cards', methods=['GET', 'POST'])
@login_required
def access_credit_cards():
    title = 'Saved Credit Cards'

    encryption_key = session['encryption_key']
    user_credit_cards = get_user_credit_cards(current_user, encryption_key)
    user_credit_cards.sort(key=lambda entry: entry.name)

    search = False
    form = SearchForm()
    if form.validate_on_submit():
        query = form.query.data
        user_credit_cards = search_credit_cards(user_credit_cards, query)
        search = True

    user_credit_cards.sort(key=lambda entry: entry.name)

    return render_template('user_data/credit_cards/credit_cards.html', title=title, form=form, entries=user_credit_cards,
                           search=search)


@user_data.route('/credit_cards/new', methods=['GET', 'POST'])
@login_required
def add_credit_card():
    title = 'Add Credit Card'

    encryption_key = session['encryption_key']
    form = NewCreditCardForm()
    if form.validate_on_submit():
        name = form.name.data
        if not name:
            name = '(unnamed)'
        name = encrypt(encryption_key, name)
        number = encrypt(encryption_key, form.number.data)
        expiration_date = encrypt(encryption_key, form.expiration_date.data)
        cvv = encrypt(encryption_key, form.cvv.data)
        cardholder_name = encrypt(encryption_key, form.cardholder_name.data)
        user = current_user
        entry = CreditCard(name=name, number=number, expiration_date=expiration_date, cvv=cvv,
                           cardholder_name=cardholder_name, user=user)
        db.session.add(entry)
        db.session.commit()
        flash('Credit Card has been saved.', 'success')
        return redirect(url_for('user_data.access_credit_cards'))

    return render_template('user_data/credit_cards/edit_credit_card.html', title=title, form=form)


@user_data.route('/credit_cards/<int:entry_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_credit_card(entry_id):
    title = 'Edit Credit Card'

    encryption_key = session['encryption_key']
    entry = CreditCard.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        abort(403)
    form = NewCreditCardForm()
    if form.validate_on_submit():
        entry.name = form.name.data
        if not entry.name:
            entry.name = '(unnamed)'
        entry.number = form.number.data
        entry.expiration_date = form.expiration_date.data
        entry.cvv = form.cvv.data
        entry.cardholder_name = form.cardholder_name.data
        entry = encrypt_credit_card(encryption_key, entry)
        db.session.commit()
        flash('Credit Card has been updated.', 'success')
        return redirect(url_for('user_data.access_credit_cards'))
    elif request.method == 'GET':
        entry = decrypt_credit_card(encryption_key, entry)
        form.name.data = entry.name
        form.number.data = entry.number
        form.expiration_date.data = entry.expiration_date
        form.cvv.data = entry.cvv
        form.cardholder_name.data = entry.cardholder_name

    return render_template('user_data/credit_cards/edit_credit_card.html', title=title, form=form)


@user_data.route('/credit_cards/<int:entry_id>/delete', methods=['POST'])
@login_required
def delete_credit_card(entry_id):
    entry = CreditCard.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        abort(403)
    db.session.delete(entry)
    db.session.commit()
    # flash('Credit Card has been deleted.', 'success')

    return redirect(url_for('user_data.access_all'))


@user_data.route('/decrypt', methods=['GET', 'POST'])
def decrypt_data():
    title = 'Decrypt Data'

    form = ImportDataForm()
    if form.validate_on_submit():
        try:
            file_contents = form.file.data.read()
            data = import_encrypted_user_data(file_contents, form.master_key.data)
        except:
            flash('Master key invalid or file corrupted!', 'danger')
            return redirect(url_for('user_data.decrypt_data'))

        decrypted_all = []
        for data_type in data:
            decrypted_all.extend(data_type)
        decrypted_all.sort(key=lambda entry: entry.name)
        empty = False if decrypted_all else True

        return render_template('user_data/decrypt_data/decrypted_data.html', title=title, entries=decrypted_all,
                               entries_count=len(decrypted_all), empty=empty)
    else:
        return render_template('user_data/decrypt_data/decrypt_data.html', title=title, form=form)


@user_data.route('/backup', methods=['GET', 'POST'])
@login_required
def backup():
    title = 'Import/Export Data'

    form = ImportDataForm()
    if form.validate_on_submit():
        try:
            file_contents = form.file.data.read()
            data = import_encrypted_user_data(file_contents, form.master_key.data)
        except:
            flash('Master key invalid or file corrupted!', 'danger')
            return redirect(url_for('user_data.backup'))

        encryption_key = session['encryption_key']
        if save_imported_user_data(data, current_user, encryption_key):
            flash('User data successfully imported.', 'success')
            return redirect(url_for('user_data.access_all'))
        else:
            flash('Something went wrong. Please try again.', 'danger')
            return redirect(url_for('user_data.backup'))

    return render_template('user_data/backup.html', title=title, form=form)


@user_data.route('/download/user_data.json')
@login_required
@nocache
def download_encrypted_user_data():
    data = export_encrypted_user_data(current_user)
    return send_file(BytesIO(data.encode()), attachment_filename='user_data.json', as_attachment=True)

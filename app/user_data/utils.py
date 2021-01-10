import json

from app import db
from app.models import Password, SecureNote, CreditCard
from app.utils.encryption import get_key, encrypt, decrypt


def get_user_passwords(user, encryption_key=None):
    user_passwords = []
    for entry in user.managed_passwords:
        if encryption_key:
            entry = decrypt_password(encryption_key, entry)
        user_passwords.append(entry)
    return user_passwords


def get_user_secure_notes(user, encryption_key=None):
    user_secure_notes = []
    for entry in user.managed_secure_notes:
        if encryption_key:
            entry = decrypt_secure_note(encryption_key, entry)
        user_secure_notes.append(entry)
    return user_secure_notes


def get_user_credit_cards(user, encryption_key=None):
    user_credit_cards = []
    for entry in user.managed_credit_cards:
        if encryption_key:
            entry = decrypt_credit_card(encryption_key, entry)
        user_credit_cards.append(entry)
    return user_credit_cards


def encrypt_password(encryption_key, entry):
    entry.name = encrypt(encryption_key, entry.name)
    entry.site = encrypt(encryption_key, entry.site)
    entry.username = encrypt(encryption_key, entry.username)
    entry.password = encrypt(encryption_key, entry.password)
    return entry


def encrypt_secure_note(encryption_key, entry):
    entry.name = encrypt(encryption_key, entry.name)
    entry.content = encrypt(encryption_key, entry.content)
    return entry


def encrypt_credit_card(encryption_key, entry):
    entry.name = encrypt(encryption_key, entry.name)
    entry.number = encrypt(encryption_key, entry.number)
    entry.expiration_date = encrypt(encryption_key, entry.expiration_date)
    entry.cvv = encrypt(encryption_key, entry.cvv)
    entry.cardholder_name = encrypt(encryption_key, entry.cardholder_name)
    return entry


def decrypt_password(encryption_key, entry):
    entry.name = decrypt(encryption_key, entry.name)
    entry.site = decrypt(encryption_key, entry.site)
    entry.username = decrypt(encryption_key, entry.username)
    entry.password = decrypt(encryption_key, entry.password)
    return entry


def decrypt_secure_note(encryption_key, entry):
    entry.name = decrypt(encryption_key, entry.name)
    entry.content = decrypt(encryption_key, entry.content)
    return entry


def decrypt_credit_card(encryption_key, entry):
    entry.name = decrypt(encryption_key, entry.name)
    entry.number = decrypt(encryption_key, entry.number)
    entry.expiration_date = decrypt(encryption_key, entry.expiration_date)
    entry.cvv = decrypt(encryption_key, entry.cvv)
    entry.cardholder_name = decrypt(encryption_key, entry.cardholder_name)
    return entry


def search_passwords(passwords, query):
    query = query.lower()
    results = []
    if passwords:
        for entry in passwords:
            if query in entry.name.lower() or query in entry.site.lower() or query in entry.username.lower():
                results.append(entry)
    return results


def search_secure_notes(secure_notes, query):
    query = query.lower()
    results = []
    if secure_notes:
        for entry in secure_notes:
            if query in entry.name.lower() or query in entry.content.lower():
                results.append(entry)
    return results


def search_credit_cards(credit_cards, query):
    query = query.lower()
    results = []
    if credit_cards:
        for entry in credit_cards:
            if query in entry.name.lower() or query in entry.number.lower() \
                    or query in entry.cardholder_name.lower():
                results.append(entry)
    return results


def check_master_key(master_key, user):
    """Checks if provided master key is valid by trying to decrypt user data with it."""
    encryption_key = get_key(master_key)

    try:
        get_user_passwords(user, encryption_key)
    except:
        return False

    try:
        get_user_secure_notes(user, encryption_key)
    except:
        return False

    try:
        get_user_credit_cards(user, encryption_key)
    except:
        return False

    return True


def reencrypt_user_data(user, old_encryption_key, new_encryption_key):
    passwords = get_user_passwords(user, old_encryption_key)
    for entry in passwords:
        entry = encrypt_password(new_encryption_key, entry)

    secure_notes = get_user_secure_notes(user, old_encryption_key)
    for entry in secure_notes:
        entry = encrypt_secure_note(new_encryption_key, entry)

    credit_cards = get_user_credit_cards(user, old_encryption_key)
    for entry in credit_cards:
        entry = encrypt_credit_card(new_encryption_key, entry)

    db.session.commit()


def export_encrypted_user_data(user, include_master_key=False):
    """Generates json with encrypted user data and optionally encrypted master key"""

    data = {'passwords': {}, 'secure_notes': {}, 'credit_cards': {}}

    if include_master_key:
        data['master_key'] = user.master_key

    passwords = get_user_passwords(user)
    for entry in passwords:
        entry.name = entry.name
        entry.site = entry.site
        entry.username = entry.username
        entry.password = entry.password

        data['passwords'][entry.id] = {'name': entry.name, 'site': entry.site,
                                       'username': entry.username, 'password': entry.password}

    secure_notes = get_user_secure_notes(user)
    for entry in secure_notes:
        entry.name = entry.name
        entry.content = entry.content

        data['secure_notes'][entry.id] = {'name': entry.name, 'content': entry.content}

    credit_cards = get_user_credit_cards(user)
    for entry in credit_cards:
        entry.name = entry.name
        entry.number = entry.number
        entry.expiration_date = entry.expiration_date
        entry.cvv = entry.cvv
        entry.cardholder_name = entry.cardholder_name

        data['credit_cards'][entry.id] = {'name': entry.name, 'number': entry.number,
                                          'expiration_date': entry.expiration_date, 'cvv': entry.cvv,
                                          'cardholder_name': entry.cardholder_name}

    return json.dumps(data, indent=4)


def import_encrypted_user_data(data, master_key):
    data = json.loads(data)
    encryption_key = get_key(master_key)

    passwords = []
    for entry_id in data['passwords']:
        entry = data['passwords'][entry_id]
        entry['name'] = entry['name']
        entry['site'] = entry['site']
        entry['username'] = entry['username']
        entry['password'] = entry['password']
        passwords.append(Password(name=entry['name'], site=entry['site'], username=entry['username'],
                         password=entry['password']))

    secure_notes = []
    for entry_id in data['secure_notes']:
        entry = data['secure_notes'][entry_id]
        entry['name'] = entry['name']
        entry['content'] = entry['content']
        secure_notes.append(SecureNote(name=entry['name'], content=entry['content']))

    credit_cards = []
    for entry_id in data['credit_cards']:
        entry = data['credit_cards'][entry_id]
        entry['name'] = entry['name']
        entry['number'] = entry['number']
        entry['expiration_date'] = entry['expiration_date']
        entry['cvv'] = entry['cvv']
        entry['cardholder_name'] = entry['cardholder_name']
        credit_cards.append(CreditCard(name=entry['name'], number=entry['number'],
                                       expiration_date=entry['expiration_date'], cvv=entry['cvv'],
                                       cardholder_name=entry['cardholder_name']))

    decrypted_passwords = []
    for entry in passwords:
        entry = decrypt_password(encryption_key, entry)
        decrypted_passwords.append(entry)

    decrypted_secure_notes = []
    for entry in secure_notes:
        entry = decrypt_secure_note(encryption_key, entry)
        decrypted_secure_notes.append(entry)

    decrypted_credit_cards = []
    for entry in credit_cards:
        entry = decrypt_credit_card(encryption_key, entry)
        decrypted_credit_cards.append(entry)

    return decrypted_passwords, decrypted_secure_notes, decrypted_credit_cards


def save_imported_user_data(data, user, encryption_key):
    passwords = data[0]
    secure_notes = data[1]
    credit_cards = data[2]

    for password in passwords:
        password.user = user
        password = encrypt_password(encryption_key, password)
        db.session.add(password)
        db.session.commit()

    for secure_note in secure_notes:
        secure_note.user = user
        secure_note = encrypt_secure_note(encryption_key, secure_note)
        db.session.add(secure_note)
        db.session.commit()

    for credit_card in credit_cards:
        credit_card.user = user
        credit_card = encrypt_credit_card(encryption_key, credit_card)
        db.session.add(credit_card)
        db.session.commit()

    return True


def process_user_data_manipulation_request(data, user):
    action = data['action']
    data_type = data['data_type']
    data = data['data']

    if action == 'add':
        entry = data

        if data_type == 'password':
            name = entry['name']
            site = entry['site']
            username = entry['username']
            password = entry['password']
            entry = Password(name=name, site=site, username=username, password=password, user=user)
            db.session.add(entry)
            db.session.commit()
            return True

        elif data_type == 'secure_note':
            name = entry['name']
            content = entry['content']
            entry = SecureNote(name=name, content=content, user=user)
            db.session.add(entry)
            db.session.commit()
            return True

        elif data_type == 'credit_card':
            name = entry['name']
            number = entry['number']
            expiration_date = entry['expiration_date'].encode()
            cvv = entry['cvv']
            cardholder_name = entry['cardholder_name']
            entry = CreditCard(name=name, number=number, expiration_date=expiration_date, cvv=cvv,
                               cardholder_name=cardholder_name, user=user)
            db.session.add(entry)
            db.session.commit()
            return True

    elif action == 'edit':
        to_edit = list(data)[0]
        entry_dict = data[to_edit]

        if data_type == 'password':
            entry_obj = Password.query.get(to_edit)
            if entry_obj and entry_obj.user_id == user.id:
                entry_obj.name = entry_dict['name']
                entry_obj.site = entry_dict['site']
                entry_obj.username = entry_dict['username']
                entry_obj.password = entry_dict['password']
                db.session.commit()
                return True

        elif data_type == 'secure_note':
            entry_obj = SecureNote.query.get(to_edit)
            if entry_obj and entry_obj.user_id == user.id:
                entry_obj.name = entry_dict['name']
                entry_obj.content = entry_dict['content']
                db.session.commit()
                return True

        elif data_type == 'credit_card':
            entry_obj = CreditCard.query.get(to_edit)
            if entry_obj and entry_obj.user_id == user.id:
                entry_obj.name = entry_dict['name']
                entry_obj.number = entry_dict['number']
                entry_obj.expiration_date = entry_dict['expiration_date']
                entry_obj.cvv = entry_dict['cvv']
                entry_obj.cardholder_name = entry_dict['cardholder_name']
                db.session.commit()
                return True

    elif action == 'delete':
        to_delete = data

        if data_type == 'password':
            entry = Password.query.get(to_delete)
            if entry and entry.user_id == user.id:
                db.session.delete(entry)
                db.session.commit()
                return True

        elif data_type == 'secure_note':
            entry = SecureNote.query.get(to_delete)
            if entry and entry.user_id == user.id:
                db.session.delete(entry)
                db.session.commit()
                return True

        elif data_type == 'credit_card':
            entry = CreditCard.query.get(to_delete)
            if entry and entry.user_id == user.id:
                db.session.delete(entry)
                db.session.commit()
                return True

    return False


def wipe_user_data(user):
    entries = []
    entries.extend(Password.query.filter_by(user_id=user.id).all())
    entries.extend(SecureNote.query.filter_by(user_id=user.id).all())
    entries.extend(CreditCard.query.filter_by(user_id=user.id).all())
    for entry in entries:
        db.session.delete(entry)
    db.session.commit()

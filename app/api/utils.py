from app import db
from app.models import Password, SecureNote, CreditCard


def process_user_data_manipulation_request(data, user):
    action = data['action']
    data_type = data['data_type']
    data = data['data']

    if action == 'add':
        entry = data

        if data_type == 'password':
            name = entry['name'].encode()
            site = entry['site'].encode()
            username = entry['username'].encode()
            password = entry['password'].encode()
            entry = Password(name=name, site=site, username=username, password=password, user=user)
            db.session.add(entry)
            db.session.commit()
            return True

        elif data_type == 'secure_note':
            name = entry['name'].encode()
            content = entry['content'].encode()
            entry = SecureNote(name=name, content=content, user=user)
            db.session.add(entry)
            db.session.commit()
            return True

        elif data_type == 'credit_card':
            name = entry['name'].encode()
            number = entry['number'].encode()
            expiration_date = entry['expiration_date'].encode()
            cvv = entry['cvv'].encode()
            cardholder_name = entry['cardholder_name'].encode()
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
                entry_obj.name = entry_dict['name'].encode()
                entry_obj.site = entry_dict['site'].encode()
                entry_obj.username = entry_dict['username'].encode()
                entry_obj.password = entry_dict['password'].encode()
                db.session.commit()
                return True

        elif data_type == 'secure_note':
            entry_obj = SecureNote.query.get(to_edit)
            if entry_obj and entry_obj.user_id == user.id:
                entry_obj.name = entry_dict['name'].encode()
                entry_obj.content = entry_dict['content'].encode()
                db.session.commit()
                return True

        elif data_type == 'credit_card':
            entry_obj = CreditCard.query.get(to_edit)
            if entry_obj and entry_obj.user_id == user.id:
                entry_obj.name = entry_dict['name'].encode()
                entry_obj.number = entry_dict['number'].encode()
                entry_obj.expiration_date = entry_dict['expiration_date'].encode()
                entry_obj.cvv = entry_dict['cvv'].encode()
                entry_obj.cardholder_name = entry_dict['cardholder_name'].encode()
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

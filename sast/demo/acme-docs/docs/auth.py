from functools import wraps

from flask import abort
from flask_login import current_user


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def audit_log(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        print("access", view.__name__)
        return view(*args, **kwargs)
    return wrapper


def can_edit(user, comment):
    return comment.author_id == user.id

import jwt
from flask import request, abort

from constants import JWT_SECRET, JWT_ALG


def auth_requered(func):
    """Ограничивает доступ для запросов без токена."""
    def wrapper(*args, **kwargs):
        if "Authorization" not in request.headers:
            abort(401)

        token = request.headers["Authorization"]
        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        except Exception as e:
            print(f"JWT decode error: {e}")
            abort(401)
        return func(*args, **kwargs)
    return wrapper


def admin_requered(func):
    """Даёт доступ только администраторам."""
    def wrapper(*args, **kwargs):
        if "Authorization" not in request.headers:
            abort(401)

        token = request.headers["Authorization"]
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        except Exception as e:
            print(f"JWT decode error: {e}")
            abort(401), f"JWT decode error: {e}"
        else:
            if data["role"] == "admin":
                return func(*args, **kwargs)
        abort(403)
    return wrapper

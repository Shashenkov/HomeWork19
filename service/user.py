import base64
import hashlib
import hmac

from dao.user import UserDAO
from constants import PWD_HASH_SALT, PWD_HASH_ITERATIONS


class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, uid):
        return self.dao.get_one(uid)

    def get_all(self):
        return self.dao.get_all()

    def get_by_username(self, username):
        return self.dao.get_by_username(username)

    def create(self, user_d):
        user_d["password"] = self.get_hash(user_d["password"])
        return self.dao.create(user_d)

    def update(self, user_d):
        self.dao.update(user_d)
        return self.dao

    def delete(self, uid):
        self.dao.delete(uid)

    def get_hash(self, password):
        """Метод генерации хеша пароля пользователя,хешируем пароли с помощью pbkdf2_hmac."""
        return base64.b64encode(hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),  # Convert the password to bytes
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        ))

    def compare_passwords(self, password, password_hash):
        """Сравнивает пароль с хешом."""
        return hmac.compare_digest(base64.b64decode(password_hash), base64.b64decode(self.get_hash(password)))

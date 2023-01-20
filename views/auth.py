from flask import request
from flask_restx import Namespace, Resource

from implemented import auth_service

auth_ns = Namespace('auth')


@auth_ns.route("/")
class AuthView(Resource):
    def post(self):
        """Возвращает access_token и refresh_token или 401. получает логин и пароль из Body запроса в виде JSON,
         далее проверяет соотвествие с данными в БД (есть ли такой пользователь, такой ли у него пароль)
         и если всё оk — генерит пару access_token и refresh_token и отдает их в виде JSON."""
        req_json = request.json
        username = req_json.get("username")
        password = req_json.get("password")
        if not (username or password):
            return "Введите username и password", 400

        tokens = auth_service.generate_tokens(username, password)
        if tokens:
            return tokens
        return "", 401

    def put(self):
        """Возвращает access_token и refresh_token или 401"""
        req_json = request.json
        ref_token = req_json.get("refresh_token")
        if not ref_token:
            return "Не задан token"

        tokens = auth_service.approve_refresh_token(ref_token)
        if tokens:
            return tokens
        return "", 401

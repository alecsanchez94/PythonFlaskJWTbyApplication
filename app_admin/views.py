from datetime import datetime, timedelta

import requests
from flask import request, render_template, current_app, jsonify
from flask_jwt_extended import create_access_token, decode_token
from flask_jwt_extended import (
    create_refresh_token, get_jwt_identity,
    jwt_required
)
from flask_mail import Message
from flask_restful import Resource
from itsdangerous import URLSafeTimedSerializer

from flask_server import jwt, ipinfo, mail, api, db
from .models import User, Role


def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=current_app.config.MAIL_DEFAULT_SENDER,

    )

    print("Sending email to {}".format(to))
    mail.send(msg)


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(current_app.config.SECRET_KEY)
    return serializer.dumps(email, salt=current_app.config.SECURITY_PASSWORD_SALT)


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config.SECRET_KEY)
    try:
        email = serializer.loads(
            token,
            salt=current_app.config.SECURITY_PASSWORD_SALT,
            max_age=expiration
        )
    except BaseException as e:
        return False
    return email


from urllib.parse import urljoin


@api.resource('/api/auth/forgotpassword/')
class API_ForgotPassword(Resource):
    def post(self):
        body = request.get_json()
        email = body.get('email')
        user = User.query.filter(User.email == email).first()

        expires = timedelta(hours=24)
        reset_token = create_access_token(str(user.id), expires_delta=expires)
        endpoint = "/password/reset/confirm/{}/{}".format(user.id, reset_token)
        url = urljoin(current_app.config.FRONTEND, endpoint)

        return send_email(subject='Reset Your Password',
                          to=user.email,
                          template=render_template('reset_password.html',
                                                   url=url))


@api.resource('/api/auth/resetpassword/')
class API_ResetPassword(Resource):
    def post(self):
        try:
            body = request.get_json()
            password = body.get('password')
            id = body.get('id')

            user = User.query.filter(User.id == id).first()

            user.password = password
            user.hash_password()
            user.save()
            email = user.email
            print(email)

            frontend_url = current_app.config.FRONTEND
            return send_email(subject='Password reset successful',
                              to=email,
                              template=render_template('password_confirmed.html',
                                                       url=frontend_url))

        except BaseException as e:
            print(e)

            return {

                       'error': str(e)

                   }, 401


@api.resource('/api/admin/roles/')
class API_Roles(Resource):
    @jwt_required()
    def get(self):
        roles = Role.query.all()
        main_dictionary = []
        for role in roles:
            main_dictionary.append(role.name)

        return (main_dictionary)

    @jwt_required()
    def post(self):
        body = request.get_json()
        action = body.get('action')
        if action == 'add':
            role = Role(name=body.get('role'))
            role.save()
        elif action == 'remove':
            roles = body.get('role')
            for r in roles['value']:
                role = Role.query.filter(Role.name == r).first()
                role.drop()

        roles = Role.query.all()
        main_dictionary = []
        for role in roles:
            main_dictionary.append(role.name)

        return main_dictionary


@api.resource('/api/admin/user/roles/')
class API_UserRoles(Resource):
    @jwt_required()
    def post(self):
        body = request.get_json()
        userID = body.get('id')
        action = body.get('action')
        roles = body.get('roles')

        user = User.query.filter(User.id == userID).first()

        if action == 'add':

            to_be_roles = user.roles
            for r in roles['value']:
                role = Role.query.filter(Role.name == r).first()
                to_be_roles.append(role)

            rolearray = []
            for r in to_be_roles:
                rolearray.append(r.name)

            user.roles = to_be_roles
            user.save()

            return user.serialize()

        elif action == 'remove':
            print("REMOVE")

            to_be_roles = []
            for r in roles['value']:
                role = Role.query.filter(Role.name == r).first()
                for _r in user.roles:
                    if _r.name != r:
                        to_be_roles.append(_r)

            rolearray = []
            for r in to_be_roles:
                rolearray.append(r.name)

            user.roles = to_be_roles
            user.save()

            return user.serialize()


@api.resource('/api/admin/users/force_activate/')
class API_UserForceConfirm(Resource):
    @jwt_required()
    def post(self):
        body = request.get_json()
        userID = body.get('id')
        user = User.query.filter(User.id == userID).first()
        user.is_activated = True
        user.save()

        return user.serialize()


@api.resource('/api/admin/users/reactivate/')
class API_UserReactivate(Resource):
    @jwt_required()
    def post(self):
        body = request.get_json()
        userID = body.get('id')

        user = User.query.filter(User.id == userID).first_or_404()
        user.deactivated = False
        user.save()
        return user.serialize()


@api.resource('/api/admin/users/deactivate/')
class API_UserDeactivate(Resource):
    @jwt_required()
    def post(self):
        body = request.get_json()
        userID = body.get('id')
        user = User.query.filter(User.id == userID).first()
        user.is_activated = False
        user.deactivated = True
        user.save()
        return user.serialize()


@api.resource('/api/users/')
class API_Users(Resource):
    @jwt_required()
    def get(self):

        users = User.query.all()
        response = []
        for user in users:
            response.append(user.serialize())

        return response

    @jwt_required()
    def post(self):
        body = request.get_json()
        userid = body.get('id')
        user = User.query.filter(User.id == userid).first_or_404()
        return [user.serialize()]

    @jwt_required()
    def put(self):
        body = request.get_json()
        message = []

        userID = body.get('id')
        user = User.query.filter(User.id == userID).first()

        valid_keys = ['email', 'password', 'first_name', 'last_name']
        keys_to_remove = []
        for key in body:
            if key not in valid_keys:
                keys_to_remove.append(key)
        for key in keys_to_remove:
            body.pop(key)

        for x in body:
            key = x
            value = body[x]
            if len(value) > 0:
                setattr(user, key, body[x])
                if key == 'password':
                    user.hash_password()

                user.save()

        return user.serialize()


@api.resource('/auth/users/me/')
class API_UserMeta(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        user = User.query.filter(User.id == user_id).first()

        return {
                   "id": user.id,
                   "email": user.email,
                   "first_name": user.first_name,
                   "last_name": user.last_name
               }, 200


@api.resource('/auth/request_acct_activation/')
class API_RequestAccountActivationEmail(Resource):
    def post(self):
        body = request.get_json()
        email = body.get('email')
        user = User.query.filter(User.email == email).first()
        send_activation_email(user)
        return {
                   'msg': 'An email has been sent for confirmation.'}, 200


@api.resource('/auth/users/create_account/')
class API_UserSignup(Resource):

    def post(self):
        try:
            body = request.get_json()
            user = User(**body)
            user.hash_password()
            user.save()
            send_activation_email(user)

            return user.serialize()
        except BaseException as e:
            return {
                       "error": str(e)
                   }, 401


def sniff_ip(ipinfo):
    current_app.logger.warning("Login from: {}".format(ipinfo.ipaddress))
    current_app.logger.info("Operating System: {}".format(ipinfo.os))
    current_app.logger.info("Browser: {}".format(ipinfo.browser))

    addr = ipinfo.ipaddress
    url = 'https://ipinfo.io/' + addr + '/json'

    response = requests.get("{}".format(url))
    for x in response.json():
        current_app.logger.info("{}: {}".format(x, response.json()[x]))


@api.resource('/auth/jwt/create/')
class API_Login(Resource):
    def post(self):
        try:
            sniff_ip(ipinfo)
            body = request.get_json()
            user = User.query.filter(User.email == body.get('email')).first()
            authorized = user.check_password(body.get('password'))

            if not user.is_activated:
                return {'error': 'Account is not activated'}, 401

            if not authorized:
                return {'error': 'Email or password invalid'}, 401

            access_token = create_access_token(identity=str(user.id))
            refresh_token = create_refresh_token(identity=str(user.id))

            return {
                       "access_token": access_token,
                       "refresh_token": refresh_token,
                       "get_full_name": "{} {}".format(user.first_name, user.last_name)
                   }, 200
        except BaseException as e:
            return {"Error": str(e)}, 401


@api.resource('/auth/jwt/refresh/')
class API_NewRefreshToken(Resource):
    @jwt_required(refresh=True)
    def post(self):
        user_id = get_jwt_identity()
        new_token = create_access_token(identity=user_id, fresh=False)
        return {'access_token': new_token}, 200


def send_activation_email(User):
    token = generate_confirmation_token(User.email)

    endpoint = "/confirm_email/{}".format(token)
    confirm_url = urljoin(current_app.config.FRONTEND, endpoint)

    html = render_template('/email_confirmation_template.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(User.email, subject, html)


def send_reset_email(User):
    expires = timedelta(hours=24)
    reset_token = create_access_token(str(User.id), expires_delta=expires)
    endpoint = "/password/reset/confirm/{}/{}".format(User.id, reset_token)
    url = urljoin(current_app.config.FRONTEND, endpoint)

    return send_email(subject='Account Created, Password Reset',
                      to=User.email,
                      template=render_template('postcreate_passwordreset.html',
                                               url=url))


@api.resource('/confirm/')
class API_ConfirmEmail(Resource):
    def post(self):
        body = request.get_json()

        token = body.get('token')
        try:
            email = confirm_token(token)
        except:
            return {
                       "msg": 'The confirmation link is invalid or has expired.'
                   }, 404
        user = User.query.filter_by(email=email).first_or_404()
        if user.is_activated:
            return {
                       "msg": "Account already confirmed. Please login."
                   }, 404
        else:
            user.is_activated = True
            user.activated_on = datetime.now()
            db.session.add(user)
            db.session.commit()
            send_reset_email(user)

            return {
                       "msg": "You have confirmed your account. Please check your email for a password reset link. Thanks!"
                   }, 200


@api.resource('/auth/jwt/verify/')
class verifyJWT(Resource):
    @jwt_required()
    def post(self):
        tkn = request.headers.get('Authorization').replace("Bearer ", "").strip()
        decode_token(tkn)
        return {
                   'message': 'Validated Access Token'
               }, 200


@jwt.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_payload):
    return jsonify(code="UNAUTHORIZED", err="Token has expired"), 401

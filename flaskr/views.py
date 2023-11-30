from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView
from . import bcrypt, db,app
from flaskr.models import User,BlacklistToken
import os
import jwt
import re

auth_blueprint = Blueprint('auth', __name__)

class RegisterAPI(MethodView):
    """
    User Registration Resource
    """

    def post(self):
        # app.logger.debug('This is a debug message')
        # app.logger.info('This is an info message')
        # app.logger.warning('This is a warning message')
        # app.logger.error('This is an error message')
        # app.logger.critical('This is a critical message')
        post_data = request.get_json()
        app.logger.info(post_data)
        # check if user already exists
        user = User.query.filter_by(email=post_data.get('email')).first()
        if not user:
            try:
                if post_data.get('role') and post_data.get('role').lower() == 'admin':
                    return jsonify({"error": "You cannot register as an admin.Please contact app owner"}), 403
                user = User(
                    email=post_data.get('email'),
                    password=post_data.get('password'),
                    username=post_data.get('username'),
                    role=post_data.get('role')
                )
                app.logger.info(user)
                # insert the user
                db.session.add(user)
                db.session.commit()

                # generate the auth token
                auth_token = user.encode_auth_token(user.user_id)
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'auth_token': auth_token
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                app.logger.error(e)
                responseObject = {
                    'status': 'fail',
                    'error': str(e)
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(responseObject)), 202

class LoginAPI(MethodView):
    """
    User Login Resource
    """
    def post(self):
        # get the post data
        post_data = request.get_json()
        try:
            # fetch the user data
            user = User.query.filter_by(
                email=post_data.get('email')
            ).first()
            if user and bcrypt.check_password_hash(
                user.password, post_data.get('password')
            ):
                auth_token = user.encode_auth_token(user.user_id)
                if auth_token:
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'User does not exist.'
                }
                return make_response(jsonify(responseObject)), 404
        except Exception as e:
            print(e)
            responseObject = {
                'status': 'fail',
                'message': str(e)
            }
            return make_response(jsonify(responseObject)), 500

class UserAPI(MethodView):
    """
    User Resource
    """
    def __init__(self):
        self.auth_header = request.headers.get('Authorization')
        self.auth_token = self.auth_header.split(" ")[1] if self.auth_header else ''
        self.current_user_id = User.decode_auth_token(self.auth_token)
        self.current_user = User.query.filter_by(user_id=self.current_user_id).first()
    def _authenticate_user(self):
        try:
            user_id = User.decode_auth_token(self.auth_token)
            if not isinstance(user_id, str):
                return user_id
            else:
                return None
        except Exception as e:
            app.logger.error(e)
            return None

    def _check_admin(self):
        user_id = self._authenticate_user()
        if user_id:
            user = User.query.filter_by(user_id=user_id).first()
            return user.role == 'admin'
        return False

    def _validate_email(self, email):
        # Email format validation using regular expression
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        return re.match(email_regex, email) is not None
    def get(self, user_id=None):
        if user_id and self._check_admin():
            # Get a specific user by user_id logic here
            user = User.query.filter_by(user_id=user_id).first()
            self.auth_token= self.current_user.encode_auth_token(self.current_user_id)
            if user:
                responseObject = {
                    'status': 'success',
                    'auth_token':self.auth_token,
                    'data': {
                        'user_id': user.user_id,
                        'email': user.email,
                        'role': user.role,
                        'registered_on': user.registration_date
                    }
                }
                return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'User not found.'
                }
                return make_response(jsonify(responseObject)), 404
        else:
            if not self._check_admin():
                responseObject = {
                    'status': 'fail',
                    'message': 'Unauthorized. Only admin users can access this resource.'
                }
                return make_response(jsonify(responseObject)), 403

            # Get all users from the database
            users = User.query.all()
            user_list = []
            for user in users:
                user_data = {
                    'user_id': user.user_id,
                    'email': user.email,
                    'role': user.role,
                    'registered_on': user.registration_date
                }
                user_list.append(user_data)
            self.auth_token= self.current_user.encode_auth_token(self.current_user_id)
            responseObject = {
                'status': 'success',
                'auth_token':self.auth_token,
                'data': user_list
            }
            return make_response(jsonify(responseObject)), 200

    def post(self):
        if not self._check_admin():
            responseObject = {
                'status': 'fail',
                'message': 'Unauthorized. Only admin users can access this resource.'
            }
            return make_response(jsonify(responseObject)), 403

        try:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
            role = data.get('role', 'labour')  # Default role if not provided

            # Validate required fields
            if not email or not password:
                responseObject = {
                    'status': 'fail',
                    'message': 'Email and password are required fields.'
                }
                return make_response(jsonify(responseObject)), 400

            # Validate email format
            if not self._validate_email(email):
                responseObject = {
                    'status': 'fail',
                    'message': 'Invalid email format.'
                }
                return make_response(jsonify(responseObject)), 400

            # Create new user
            new_user = User(email=email, password=password, role=role)
            db.session.add(new_user)
            db.session.commit()
            self.auth_token= self.current_user.encode_auth_token(self.current_user_id)
            responseObject = {
                'status': 'success',
                'auth_token':self.auth_token,
                'message': 'User created successfully!'
            }
            return make_response(jsonify(responseObject)), 201

        except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': str(e)
            }
            return make_response(jsonify(responseObject)), 500

    def put(self, user_id):
        if not self._check_admin():
            responseObject = {
                'status': 'fail',
                'message': 'Unauthorized. Only admin users can access this resource.'
            }
            return make_response(jsonify(responseObject)), 403

        try:
            data = request.get_json()
            email = data.get('email')
            role = data.get('role', 'labour')  # Default role if not provided
            has_work= data.get('has_work')
            # Validate email format
            if email and not self._validate_email(email):
                responseObject = {
                    'status': 'fail',
                    'message': 'Invalid email format.'
                }
                return make_response(jsonify(responseObject)), 400

            user = User.query.filter_by(user_id=user_id).first()

            if not user:
                responseObject = {
                    'status': 'fail',
                    'message': 'User not found.'
                }
                return make_response(jsonify(responseObject)), 404

            # Update user details
            user.email = email if email else user.email
            user.role = role if role else user.role
            user.has_work = has_work if has_work else user.has_work
            db.session.commit()
            self.auth_token= self.current_user.encode_auth_token(self.current_user_id)
            responseObject = {
                'status': 'success',
                'auth_token':self.auth_token,
                'message': 'User updated successfully!'
            }
            return make_response(jsonify(responseObject)), 200

        except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': str(e)
            }
            return make_response(jsonify(responseObject)), 500

    def delete(self, user_id):
        if not self._check_admin():
            responseObject = {
                'status': 'fail',
                'message': 'Unauthorized. Only admin users can access this resource.'
            }
            return make_response(jsonify(responseObject)), 403

        try:
            user = User.query.filter_by(user_id=user_id).first()

            if not user:
                responseObject = {
                    'status': 'fail',
                    'message': 'User not found.'
                }
                return make_response(jsonify(responseObject)), 404

            # Delete user
            db.session.delete(user)
            db.session.commit()
            self.auth_token= self.current_user.encode_auth_token(self.current_user_id)
            responseObject = {
                'status': 'success',
                'auth_token':self.auth_token,
                'message': 'User deleted successfully!'
            }
            return make_response(jsonify(responseObject)), 200

        except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': str(e)
            }
            return make_response(jsonify(responseObject)), 500

class LogoutAPI(MethodView):
    """
    Logout Resource
    """
    def post(self):
        # get auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                # mark the token as blacklisted
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    # insert the token
                    db.session.add(blacklist_token)
                    db.session.commit()
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                    return make_response(jsonify(responseObject)), 200
                except Exception as e:
                    responseObject = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


registration_view = RegisterAPI.as_view('register_api')
logout_view = LogoutAPI.as_view('logout_api')
login_view = LoginAPI.as_view('login_view')
user_view = UserAPI.as_view('user_api')

auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST']
)

auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)

auth_blueprint.add_url_rule(
    '/auth/users',
    view_func=user_view,
    methods=['GET', 'POST']
)

auth_blueprint.add_url_rule(
    '/auth/users/<int:user_id>',
    view_func=user_view,
    methods=['GET', 'PUT', 'DELETE']
)
auth_blueprint.add_url_rule(
    '/auth/logout',
    view_func=logout_view,
    methods=['POST']
)






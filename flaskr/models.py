from flask_sqlalchemy import SQLAlchemy
import jwt
from . import app,db,bcrypt
import os
import datetime
from sqlalchemy import Enum
import pytz


# Define your models here (e.g., User, Test, etc.)
class BlacklistToken(db.Model):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.now()

    def __repr__(self):
        return '<id: token: {}'.format(self.token)

    @staticmethod
    def check_blacklist(auth_token):
        # check whether auth token has been blacklisted
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        else:
            return False
class User(db.Model): 
    __tablename__ = 'users'  # Specify the table name if it's different from the class name
    
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(15), nullable=True)
    registration_date = db.Column(db.DateTime, server_default=db.func.current_timestamp(), nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    is_verified = db.Column(db.Boolean, nullable=True, default=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    role = db.Column(Enum('driver', 'labour','admin'), default='labour', nullable=False)
    has_work= db.Column(db.Boolean,nullable=False,default=False)
    updated_at = db.Column(db.TIMESTAMP, nullable=True, default=None, onupdate=datetime.datetime.now())
    activities = db.relationship('UserActivity', backref=db.backref('users', lazy=True))

    def __init__(self, email, password, phone_number=None,full_name=None, birthdate=None,
                 is_verified=False,
                is_admin=False, role='labour'):
        try:
            
            self.email = email
            self.password = bcrypt.generate_password_hash(
                password, int(os.getenv('BCRYPT_LOG_ROUNDS'))
            ).decode()
            self.full_name = full_name
            self.phone_number = phone_number
            self.is_verified = is_verified
            self.is_admin = is_admin
            self.role = role
        except Exception as e:
            return str(e)
    def encode_auth_token(self, user_id):
        """
        Generates the Auth Token with correct timezone
        :return: string
        """
        try:
            # Use UTC timezone for token expiration and issued at times
            utc_now = datetime.datetime.now(pytz.utc)
            expiration = utc_now + datetime.timedelta(days=0, seconds=1000)
            issued_at = utc_now

            payload = {
                'exp': expiration,
                'iat': issued_at,
                'sub': user_id,
            }
            
            # Encode the token using the correct timezone
            return jwt.encode(payload, os.getenv('SECRET_KEY'), algorithm='HS256')
        except Exception as e:
            app.logger.error(e)
            return None
        
    
    @staticmethod
    def decode_auth_token(auth_token):
        """
        Validates the auth token with correct timezone
        :param auth_token:
        :return: integer|string
        """
        try:
            # Decode the token using the secret key and UTC timezone
            payload = jwt.decode(auth_token, os.getenv('SECRET_KEY'), algorithms=['HS256'], options={'verify_exp': False})
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            # Convert the UNIX timestamp (payload['exp']) to a datetime object in UTC timezone
            exp_time_utc = datetime.datetime.fromtimestamp(payload['exp'], tz=pytz.utc)

            # Convert the UNIX timestamp to local time
            local_now = datetime.datetime.now(pytz.timezone('America/New_York'))  # Replace 'America/New_York' with your actual timezone

            # Check token expiration against local time
            if exp_time_utc < local_now:
                return 'Token expired. Please log in again.'
            else:
                return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'


    # def __repr__(self):
    #     return f'<User {self.username}>'
class Property(db.Model):
    __tablename__ = 'properties'

    property_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    property_name = db.Column(db.String(100), nullable=False)
    property_description = db.Column(db.Text, nullable=True)
    land_area_acres = db.Column(db.Float, nullable=False)
    location = db.Column(db.String(255), nullable=True)
    purchase_date = db.Column(db.DateTime, nullable=True)
    admin_created_by = db.Column(db.Integer, nullable=True)
    purchase_cost = db.Column(db.Numeric(12, 2), nullable=True)
    estimated_work = db.Column(db.Numeric(12, 2), nullable=True)
    completed_work = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.TIMESTAMP, nullable=True, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.TIMESTAMP, nullable=True, default=None, onupdate=datetime.datetime.utcnow)
    cost_to_labour = db.Column(db.Float, nullable=False)
    cost_to_driver = db.Column(db.Float, nullable=False)
    # workOrders = db.relationship('WorkOrder', backref='properties',lazy=True)

    def __init__(self, property_name, land_area_acres, location, 
                 admin_created_by, purchase_cost,purchase_date, estimated_work,
                 completed_work=0.0, cost_to_labour=0.0, cost_to_driver=0.0):
        try:
            self.property_name = property_name
            self.land_area_acres = land_area_acres
            self.location = location
            self.admin_created_by = admin_created_by
            self.purchase_date = purchase_date
            self.purchase_cost = purchase_cost
            self.estimated_work = estimated_work
            self.completed_work = completed_work
            self.cost_to_labour = cost_to_labour
            self.cost_to_driver = cost_to_driver
        except Exception as e:
            app.logger.error(e)

    def serialize(self):
        return {
            'property_id': self.property_id,
            'property_name': self.property_name,
            'property_description': self.property_description,
            'land_area_acres': self.land_area_acres,
            'location': self.location,
            'purchase_date': self.purchase_date.strftime('%Y-%m-%d %H:%M:%S') if self.purchase_date else None,
            'admin_created_by': self.admin_created_by,
            'purchase_cost': float(self.purchase_cost) if self.purchase_cost is not None else None,
            'estimated_work': float(self.estimated_work) if self.estimated_work is not None else None,
            'completed_work': self.completed_work,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S') if self.updated_at else None,
            'cost_to_labour': self.cost_to_labour,
            'cost_to_driver': self.cost_to_driver
        }

class WorkOrder(db.Model):
    __tablename__ = 'work_orders'
    
    work_order_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    property_id = db.Column(db.Integer, db.ForeignKey('properties.property_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=True)
    assigned_date = db.Column(db.DateTime, nullable=True)
    is_completed = db.Column(db.Boolean, default=False)
    total_work_done = db.Column(db.Float, nullable=True)
    update_date = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    total_earnings = db.Column(db.Float, default=0)
    # Define relationships with other tables
    property = db.relationship('Property', backref=db.backref('work_orders', lazy=True,uselist=False))
    user = db.relationship('User',primaryjoin='WorkOrder.user_id == User.user_id', backref=db.backref('work_orders', lazy=True))
    WorkRecords = db.relationship('WorkRecord',backref=db.backref('work_orders',lazy=True))
   
class WorkRecord(db.Model):
    __tablename__ = 'work_records'

    record_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    work_order_id = db.Column(db.Integer, db.ForeignKey('work_orders.work_order_id'))
    work_date = db.Column(db.DateTime, nullable=True)
    work_done_tons = db.Column(db.Float, nullable=True)
    proof_of_work_file_path = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    is_verified = db.Column(db.Boolean, default=False)
    #total_earnings= db.Column(db.Float,default=0,nullable=True)

    # Define relationship with work_orders table
    #work_order = db.relationship('WorkOrder',backref=db.backref('work_records',lazy=True))

class UserActivity(db.Model):
    __tablename__ = 'useractivity'

    activity_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=True)
    activity_type = db.Column(db.String(255), nullable=True)
    activity_description = db.Column(db.Text, nullable=True)
    activity_date = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Define relationship with users table
    # user = db.relationship('User', backref=db.backref('useractivity',lazy=True))

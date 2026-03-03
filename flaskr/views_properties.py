from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView
from . import bcrypt, db,app
from flaskr.models import User,BlacklistToken,Property,WorkOrder,WorkRecord
import os
import jwt
import re
from datetime import datetime
from flaskr.schemas import PropertySchema, WorkOrderSchema,WorkRecordSchema
from flask import send_file
import mimetypes
import base64
from sqlalchemy.orm import joinedload

property_blueprint=Blueprint("property",__name__)


def _parse_assignment_ids(data):
    assigned_labour_id = data.get('assigned_labour_id')
    assigned_driver_id = data.get('assigned_driver_id')
    assigned_labour_id = None if assigned_labour_id in (None, '') else assigned_labour_id
    assigned_driver_id = None if assigned_driver_id in (None, '') else assigned_driver_id

    if assigned_labour_id is None and assigned_driver_id is None:
        return None, None, ('At least one of assigned_labour_id or assigned_driver_id is required.', 400)

    try:
        if assigned_labour_id is not None:
            assigned_labour_id = int(assigned_labour_id)
        if assigned_driver_id is not None:
            assigned_driver_id = int(assigned_driver_id)
    except (TypeError, ValueError):
        return None, None, ('assigned_labour_id and assigned_driver_id must be valid user IDs.', 400)

    if (
        assigned_labour_id is not None
        and assigned_driver_id is not None
        and assigned_labour_id == assigned_driver_id
    ):
        return None, None, ('assigned_labour_id and assigned_driver_id must be different users.', 400)

    return assigned_labour_id, assigned_driver_id, None


def _validate_assignment_users(assigned_labour_id, assigned_driver_id):
    labour_user = None
    driver_user = None
    if assigned_labour_id is not None:
        labour_user = User.query.filter_by(user_id=assigned_labour_id).first()
        if not labour_user:
            return None, None, ('Assigned labour user not found.', 404)
        if labour_user.role != 'labour':
            return None, None, ('assigned_labour_id must belong to a labour user.', 400)
    if assigned_driver_id is not None:
        driver_user = User.query.filter_by(user_id=assigned_driver_id).first()
        if not driver_user:
            return None, None, ('Assigned driver user not found.', 404)
        if driver_user.role != 'driver':
            return None, None, ('assigned_driver_id must belong to a driver user.', 400)

    return labour_user, driver_user, None

class PropertyAPI(MethodView):
    def __init__(self):
        try:
            self.auth_header = request.headers.get('Authorization')
            self.auth_token = self.auth_header.split(" ")[1] if self.auth_header else ''
            self.current_user_id = User.decode_auth_token(self.auth_token)
            self.is_admin=False
            if isinstance(self.current_user_id,str) :
                self.is_token_error = True
            else:
                self.is_token_error = False
                self.current_user = User.query.filter_by(user_id=self.current_user_id).first()
                self.is_admin = self.current_user.role == 'admin'     
        except Exception as e:
            app.logger.error(e)
        
    def post(self):
        try:
            if self.is_token_error or not self.is_admin :
                responseObject = {
                        'status': 'fail',
                        'message': 'Unauthorized or Invalid token. Please check your role permissions and log in again '
                    }
                return make_response(jsonify(responseObject)), 403
            
            else:
                data=request.get_json() or {}
                property_in_db = Property.query.filter_by(property_name=data.get('property_name')).first()
                if not property_in_db:
                    property_name = data.get('property_name')
                    estimated_work= data.get('estimated_work')
                    land_area_acres = data.get('land_area_acres')
                    purchase_cost = data.get('purchase_cost')
                    purchase_date_str = data.get('purchase_date')
                    purchase_date_obj = datetime.strptime(purchase_date_str, "%m-%d-%Y")
                    location= data.get('location')
                    admin_created_by= self.current_user_id
                    cost_to_labour=data.get('cost_to_labour')
                    cost_to_driver=data.get('cost_to_driver')

                    assigned_labour_id, assigned_driver_id, parse_error = _parse_assignment_ids(data)
                    if parse_error:
                        responseObject = {'status': 'fail', 'message': parse_error[0]}
                        return make_response(jsonify(responseObject)), parse_error[1]

                    labour_user, driver_user, user_error = _validate_assignment_users(
                        assigned_labour_id, assigned_driver_id
                    )
                    if user_error:
                        responseObject = {'status': 'fail', 'message': user_error[0]}
                        return make_response(jsonify(responseObject)), user_error[1]

                    property = Property(property_name=property_name,admin_created_by=admin_created_by,estimated_work=estimated_work,
                                        purchase_cost=purchase_cost,land_area_acres=land_area_acres,
                                        purchase_date=purchase_date_obj,location=location,
                                        cost_to_driver=cost_to_driver,cost_to_labour=cost_to_labour,
                                        completed_work=0)
                    db.session.add(property)
                    db.session.flush()
                    property_id = property.property_id

                    created_work_orders = []
                    for assigned_user in (labour_user, driver_user):
                        if not assigned_user:
                            continue
                        work_order = WorkOrder(
                            property_id=property_id,
                            user_id=assigned_user.user_id,
                            assigned_date=datetime.now(),
                            is_completed=False,
                            total_work_done=0,
                            total_earnings=0
                        )
                        assigned_user.has_work = True
                        assigned_user.updated_at = datetime.now()
                        db.session.add(work_order)
                        created_work_orders.append(work_order)

                    db.session.commit()
                    self.auth_token= self.current_user.encode_auth_token(self.current_user_id)
                    responseObject = {
                        'status': 'success',
                        'message': 'Property and work orders created successfully!',
                        'property_id': property_id,
                        'work_order_ids': [wo.work_order_id for wo in created_work_orders]
                    }
                    return make_response(jsonify(responseObject)), 201
                else:
                    responseObject = {
                        'status': 'fail',
                        'message': 'Property already exist',
                    }
                    return make_response(jsonify(responseObject)), 202
        except Exception as e:
            app.logger.error('property record commit error ' + str(e))
            db.session.rollback()  # Rollback the transaction in case of an error
            responseObject = {
                'status': 'fail',
                'message': 'Error occurred while adding property'
            }
            return make_response(jsonify(responseObject)), 500
    def get(self, property_id=None):
        try:
            if self.is_token_error:
                responseObject = {
                        'status': 'fail',
                        'message': 'Invalid token. Please check log in again '
                    }
                return make_response(jsonify(responseObject)), 403
            else: 
                if self.is_admin and not property_id:
                    properties = Property.query.all()
                    property_schema = PropertySchema(many=True)
                    properties = (property_schema.dump(properties))   
                    #app.logger.info(property_list)
                    responseObject = {
                                        'status': 'success',
                                        'data': properties
                                    }
                    return make_response(jsonify(responseObject)), 200
                elif self.is_admin and property_id:
                    property = Property.query.filter_by(property_id=property_id).first()
                    property_schema = PropertySchema()
                    property = property_schema.dump(property)
                    #work_orders = WorkOrder.query.filter_by(property_id=property_id).all()
                    work_orders = WorkOrder.query.options(joinedload(WorkOrder.user)).filter_by(property_id=property_id).all()
                    work_order_schema=WorkOrderSchema(many=True)
                    work_orders = work_order_schema.dump(work_orders)
                    # Add work_records to each work_order
                    for work_order in work_orders:
                        #print(work_order['user_full_name'])
                        work_records = WorkRecord.query.filter_by(work_order_id=work_order['work_order_id']).all()
                        work_record_schema = WorkRecordSchema(many=True)
                        work_records = work_record_schema.dump(work_records)
                        for work_record in work_records:
                            try:
                                with open(work_record['proof_of_work_file_path'], 'rb') as image_file:
                                    encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
                                work_record['proof_of_work_file_path'] = encoded_string
                            except FileNotFoundError:
                                work_record['proof_of_work_file_path'] = None

                        work_order['work_records'] = work_records
                        
                    responseObject = {
                                        'status': 'success',
                                        'data': [{'property':property,'work_orders': [work_orders]}]
                                    }
                    return make_response(jsonify(responseObject)), 200
                elif not self.is_admin:
                    property_schema = PropertySchema()
                    work_order_schema=WorkOrderSchema(many=True)  
                    if not property_id:  
                        current_work_orders = db.session.query(WorkOrder.work_order_id,
                                                    WorkOrder.property_id,
                                                    WorkOrder.user_id,
                                                    WorkOrder.assigned_date,
                                                    WorkOrder.is_completed,
                                                    WorkOrder.total_work_done,
                                                    WorkOrder.update_date,
                                                    WorkOrder.total_earnings,
                                                    Property.property_name,
                                                    Property.location).\
                                    outerjoin(Property, WorkOrder.property_id == Property.property_id).\
                                    outerjoin(User, WorkOrder.user_id == User.user_id).\
                                    filter(WorkOrder.user_id == self.current_user_id, WorkOrder.is_completed == False).\
                                    all()
                        #WorkOrder.query.filter_by(user_id=self.current_user_id).filter_by(is_completed=False).all()
                        #print(str(current_work_orders.statement))
                        current_work_orders =work_order_schema.dump(current_work_orders)
                        print(current_work_orders)
                        previous_work_orders = WorkOrder.query.filter_by(user_id=self.current_user_id).filter_by(is_completed=True).all()
                        previous_work_orders=work_order_schema.dump(previous_work_orders)
                        responseObject = {
                                            'status': 'success',
                                            'data': [{'current_work_orders':current_work_orders,'previous_work_orders':previous_work_orders}],
                                            'work_orders': []
                                        }
                        return make_response(jsonify(responseObject)), 200
                    else:
                        work_orders = WorkOrder.query.filter_by(user_id=self.current_user_id).filter_by(property_id=property_id).all()
                        work_orders =work_order_schema.dump(current_work_orders)
                        if not len(current_work_orders):
                            responseObject = {
                                            'status': 'success',
                                            'message': 'This property has not been assigned to you'
                                        }
                            return make_response(jsonify(responseObject)), 200
                        else:
                            #location,acerage,estimated_tonnage,work_done
                            property_data=Property.query.filter_by(property_id=property_id).with_entities([]).first()



        except Exception as e:
            app.logger.error('property record get error ' + str(e))
            responseObject = {
                'status': 'fail',
                'message': 'Error occurred while fetching properties'
            }
            return make_response(jsonify(responseObject)), 500

    def put(self, property_id):
        try:
            if self.is_token_error or not self.is_admin:
                responseObject = {
                    'status': 'fail',
                    'message': 'Unauthorized or Invalid token. Please check your role permissions and log in again '
                }
                return make_response(jsonify(responseObject)), 403

            property_record = Property.query.filter_by(property_id=property_id).first()
            if not property_record:
                responseObject = {
                    'status': 'fail',
                    'message': 'Property not found.'
                }
                return make_response(jsonify(responseObject)), 404

            data = request.get_json() or {}

            incoming_name = data.get('property_name')
            if incoming_name and incoming_name != property_record.property_name:
                existing_property = Property.query.filter_by(property_name=incoming_name).first()
                if existing_property and existing_property.property_id != property_id:
                    responseObject = {
                        'status': 'fail',
                        'message': 'Property name already exists.'
                    }
                    return make_response(jsonify(responseObject)), 409

            if incoming_name is not None:
                property_record.property_name = incoming_name
            if data.get('estimated_work') is not None:
                property_record.estimated_work = data.get('estimated_work')
            if data.get('land_area_acres') is not None:
                property_record.land_area_acres = data.get('land_area_acres')
            if data.get('purchase_cost') is not None:
                property_record.purchase_cost = data.get('purchase_cost')
            if data.get('location') is not None:
                property_record.location = data.get('location')
            if data.get('cost_to_labour') is not None:
                property_record.cost_to_labour = data.get('cost_to_labour')
            if data.get('cost_to_driver') is not None:
                property_record.cost_to_driver = data.get('cost_to_driver')

            purchase_date_str = data.get('purchase_date')
            if purchase_date_str:
                property_record.purchase_date = datetime.strptime(purchase_date_str, "%m-%d-%Y")

            property_record.updated_at = datetime.utcnow()
            db.session.commit()

            responseObject = {
                'status': 'success',
                'message': 'Property updated successfully.'
            }
            return make_response(jsonify(responseObject)), 200
        except ValueError:
            db.session.rollback()
            responseObject = {
                'status': 'fail',
                'message': 'Invalid purchase_date format. Expected MM-DD-YYYY.'
            }
            return make_response(jsonify(responseObject)), 400
        except Exception as e:
            app.logger.error('property record update error ' + str(e))
            db.session.rollback()
            responseObject = {
                'status': 'fail',
                'message': 'Error occurred while updating property'
            }
            return make_response(jsonify(responseObject)), 500


class PropertyWorkOrderAPI(MethodView):
    def __init__(self):
        try:
            self.auth_header = request.headers.get('Authorization')
            self.auth_token = self.auth_header.split(" ")[1] if self.auth_header else ''
            self.current_user_id = User.decode_auth_token(self.auth_token)
            self.is_admin = False
            if isinstance(self.current_user_id, str):
                self.is_token_error = True
            else:
                self.is_token_error = False
                self.current_user = User.query.filter_by(user_id=self.current_user_id).first()
                self.is_admin = self.current_user.role == 'admin'
        except Exception as e:
            app.logger.error(e)

    def post(self, property_id):
        try:
            if self.is_token_error or not self.is_admin:
                responseObject = {
                    'status': 'fail',
                    'message': 'Unauthorized or Invalid token. Please check your role permissions and log in again '
                }
                return make_response(jsonify(responseObject)), 403

            property_record = Property.query.filter_by(property_id=property_id).first()
            if not property_record:
                responseObject = {'status': 'fail', 'message': 'Property not found.'}
                return make_response(jsonify(responseObject)), 404

            data = request.get_json() or {}
            assigned_labour_id, assigned_driver_id, parse_error = _parse_assignment_ids(data)
            if parse_error:
                responseObject = {'status': 'fail', 'message': parse_error[0]}
                return make_response(jsonify(responseObject)), parse_error[1]

            labour_user, driver_user, user_error = _validate_assignment_users(
                assigned_labour_id, assigned_driver_id
            )
            if user_error:
                responseObject = {'status': 'fail', 'message': user_error[0]}
                return make_response(jsonify(responseObject)), user_error[1]

            created_work_orders = []
            for assigned_user in (labour_user, driver_user):
                if not assigned_user:
                    continue
                work_order = WorkOrder(
                    property_id=property_id,
                    user_id=assigned_user.user_id,
                    assigned_date=datetime.now(),
                    is_completed=False,
                    total_work_done=0,
                    total_earnings=0
                )
                assigned_user.has_work = True
                assigned_user.updated_at = datetime.now()
                db.session.add(work_order)
                created_work_orders.append(work_order)

            db.session.commit()
            responseObject = {
                'status': 'success',
                'message': 'New work orders created successfully.',
                'property_id': property_id,
                'work_order_ids': [wo.work_order_id for wo in created_work_orders]
            }
            return make_response(jsonify(responseObject)), 201
        except Exception as e:
            app.logger.error('property work order commit error ' + str(e))
            db.session.rollback()
            responseObject = {
                'status': 'fail',
                'message': 'Error occurred while creating work orders'
            }
            return make_response(jsonify(responseObject)), 500
            
                

    
properties_view = PropertyAPI.as_view('property_api')
property_work_order_view = PropertyWorkOrderAPI.as_view('property_work_order_api')
property_blueprint.add_url_rule(
    '/api/property',
    view_func=properties_view,
    methods=['POST']
)
property_blueprint.add_url_rule(
    '/api/property/<int:property_id>',
    view_func=properties_view,
    methods=['GET', 'PUT', 'DELETE']
)
property_blueprint.add_url_rule(
    '/api/property',
    view_func=properties_view,
    methods=['GET']
)
property_blueprint.add_url_rule(
    '/api/property/<int:property_id>/work_order',
    view_func=property_work_order_view,
    methods=['POST']
)

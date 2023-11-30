from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView
from . import bcrypt, db,app
from flaskr.models import User,BlacklistToken,Property,WorkOrder
import os
import jwt
import re
from datetime import datetime
from flaskr.schemas import PropertySchema, WorkOrderSchema

property_blueprint=Blueprint("property",__name__)

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
                data=request.get_json()
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
                    assigned_to= data.get('assigne_labour')
                    cost_to_labour=data.get('cost_to_labour')
                    cost_to_driver=data.get('cost_to_driver')
                    property = Property(property_name=property_name,admin_created_by=admin_created_by,estimated_work=estimated_work,
                                        purchase_cost=purchase_cost,land_area_acres=land_area_acres,
                                        purchase_date=purchase_date_obj,location=location,
                                        cost_to_driver=cost_to_driver,cost_to_labour=cost_to_labour,
                                        completed_work=0)
                    # Add the property object to the session and commit the transaction
                    db.session.add(property)
                    db.session.commit()  # Commit the transaction here
                    property_id = property.property_id
                    for user in set(assigned_to):
                        work_order = WorkOrder(property_id=property_id, user_id=user,
                                            assigned_date=datetime.now(), is_completed=False,
                                            total_work_done=0, total_earnings=0)
                        user = User.query.filter_by(user_id=user).first()
                        user.has_work=True
                        user.updated_at = datetime.now()
                        db.session.add(user)
                        db.session.add(work_order)
                    db.session.commit()  # Commit the outer transaction here
                    self.auth_token= self.current_user.encode_auth_token(self.current_user_id)
                    responseObject = {
                        'status': 'success',
                        'message': 'Property and workOrder created successfully!'
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
                    work_orders = WorkOrder.query.filter_by(property_id=property_id).all()
                    work_order_schema=WorkOrderSchema(many=True)
                    work_orders = work_order_schema.dump(work_orders)
                    
                    responseObject = {
                                        'status': 'success',
                                        'data': [{'property':property,'work_orders': [work_orders]}]
                                    }
                    return make_response(jsonify(responseObject)), 200
                elif not self.is_admin:
                    property_schema = PropertySchema()
                    work_order_schema=WorkOrderSchema(many=True)  
                    if not property_id:  
                        current_work_orders = WorkOrder.query.filter_by(user_id=self.current_user_id).filter_by(is_completed=False).all()
                        current_work_orders =work_order_schema.dump(current_work_orders)
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
            
                

    
properties_view = PropertyAPI.as_view('property_api')
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
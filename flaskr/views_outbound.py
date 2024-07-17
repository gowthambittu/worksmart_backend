from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView
from . import bcrypt, db,app
from flaskr.models import OutboundRecord, User, UserActivity
from datetime import datetime
from flaskr.schemas import OutboundRecordSchema
import base64
from flask import send_from_directory
import os

outbound_record_blueprint = Blueprint("outbound_record", __name__)

class OutboundRecordAPI(MethodView):
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
                self.current_user_role = self.current_user.role
                self.is_admin = self.current_user.role == 'admin'
        except Exception as e:
            app.logger.error(e)

    def post(self):
        try:
            if self.is_token_error and not self.is_admin:
                responseObject = {
                    'status': 'fail',
                    'message': 'Provide a valid auth token or you are not an admin.'
                }
                return make_response(jsonify(responseObject)), 401
            # Assuming you have a method to validate and process the outbound record data
            data = request.form
            file = request.files.get('receipt_proof')
            if not data['weight_in_tons'] or not data['truck_number'] or not file:
                   responseObject = {
                        'status': 'fail',
                        'message': 'Invalid Request, please provide necessary fields'
                             }
                   return make_response(jsonify(responseObject)), 400
            if file:
                # Save the file to the uploads folder
                filename = os.path.join(app.config['OUTBOUND_FOLDER'], file.filename)
                file.save(filename)
                
                new_outbound_record = OutboundRecord(
                    weight_in_tons=data['weight_in_tons'],
                    truck_number=data['truck_number'],
                    receipt_proof=filename,
                    created_id=self.current_user_id,
                    truck_date = data['truck_date'],
                )
                
                db.session.add(new_outbound_record)
                db.session.commit()

                responseObject = {
                    'status': 'success',
                    'message': 'Outbound record successfully created.'
                }
                user_activity = UserActivity(self.current_user_id, f'outbound record for truck number {new_outbound_record.truck_number} created','POST',)
                user_activity.log_activity()
                return make_response(jsonify(responseObject)), 201
        except Exception as e:
            db.session.rollback()
            responseObject = {
                'status': 'fail',
                'message': 'Error in creating outbound record.',
                'error': str(e)
            }
            return make_response(jsonify(responseObject)), 500
    def put(self):
        try:
            if self.is_token_error:
                responseObject = {
                            'status': 'fail',
                            'message': 'Invalid token. Please log in again '
                        }
                return make_response(jsonify(responseObject)), 403
            else:
                data = request.get_json()
                outbound_id = data.get('outbound_id')
                if not outbound_id:
                    responseObject = {
                                'status': 'fail',
                                'message': 'Invalid Request, please provide necessary fields'
                                    }
                    return make_response(jsonify(responseObject)), 400
                if outbound_id and self.is_admin:
                    outbound_record = OutboundRecord.query.filter_by(outbound_id=outbound_id).first()
                    print(outbound_record)
                    if not outbound_record:
                        responseObject = {
                                'status': 'error',
                                'message': 'Record not found'
                                    }
                        return make_response(jsonify(responseObject)), 404
                    if 'is_verified' in data:
                        is_verified = data.get('is_verified') == '1'
                        outbound_record.is_verified = is_verified
                        db.session.commit()
                        responseObject = {
                        'status': 'success',
                        'message': f'Outbound truck number {outbound_record.truck_number} updated successfully'
                        }
                        user_activity = UserActivity(self.current_user_id, f'Outbound Record {outbound_record.truck_number} Updated','PUT',)
                        user_activity.log_activity()
                        return make_response(jsonify(responseObject)), 200
                    else:
                        responseObject = {
                        'status': 'error',
                        'message': f'Missing or invalid is_verified value'
                        }
                        return make_response(jsonify(responseObject)), 400 
        except Exception as e:
            app.logger.error('outbound record commit error ' + str(e))
            db.session.rollback()  # Rollback the transaction in case of an error
            responseObject = {
                'status': 'fail',
                'message': 'Error occurred while updating outbound record'
            }
            return make_response(jsonify(responseObject)), 500
    def get(self):
        try:
            if self.is_token_error:
                responseObject = {
                        'status': 'fail',
                        'message': 'Invalid token. Please check log in again '
                    }
                return make_response(jsonify(responseObject)), 403
            else: 
                if self.is_admin :
                    outbound = OutboundRecord.query.all()
                    outbound_schema = OutboundRecordSchema(many=True)
                    outbound_records = (outbound_schema.dump(outbound))   
                    for record in outbound_records:
                            try:
                                with open(record['receipt_proof'], 'rb') as image_file:
                                    encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
                                record['receipt_proof'] = encoded_string
                            except FileNotFoundError:
                                record['receipt_proof'] = None
                    responseObject = {
                                        'status': 'success',
                                        'data': outbound_records
                                    }
                return make_response(jsonify(responseObject)), 200
        except Exception as e:
            app.logger.error('property record get error ' + str(e))
            responseObject = {
                'status': 'fail',
                'message': 'Error occurred while fetching properties'
            }
            return make_response(jsonify(responseObject)), 500
            

        
outbound_record_view = OutboundRecordAPI.as_view('outbound_record_api')

@outbound_record_blueprint.route('/outbound_records/<path:filename>')
def serve_work_record(filename):
    directory, filename = os.path.split(filename)
    return send_from_directory(directory, filename)        

# Register the API endpoints

outbound_record_blueprint.add_url_rule(
    '/api/outbound_record', 
    view_func=outbound_record_view, 
    methods=['POST']
    )

outbound_record_blueprint.add_url_rule(
    '/api/outbound_record', 
    view_func=outbound_record_view, 
    methods=['PUT']
    )

outbound_record_blueprint.add_url_rule(
    '/api/outbound_record', 
    view_func=outbound_record_view, 
    methods=['GET']
    )
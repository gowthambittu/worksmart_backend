from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView
from . import bcrypt, db,app
from flaskr.models import User,BlacklistToken,Property,WorkOrder,WorkRecord,UserActivity
from datetime import datetime
from flaskr.schemas import PropertySchema, WorkOrderSchema
from flask import send_from_directory
import os

work_record_blueprint=Blueprint("work_record",__name__)

class WorkRecordAPI(MethodView):
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
                self.current_user_role = self.current_user.role
                self.is_admin = self.current_user.role == 'admin'     
        except Exception as e:
            app.logger.error(e)
    def post(self):
        try:
            if self.is_token_error:
                responseObject = {
                        'status': 'fail',
                        'message': 'Invalid token. Please log in again '
                    }
                return make_response(jsonify(responseObject)), 403
            else:
                data = request.form
                file = request.files.get('proof_of_work')
                if not data['work_done_tons'] or not data['work_order_id'] or not file:
                   responseObject = {
                        'status': 'fail',
                        'message': 'Invalid Request, please provide necessary fields'
                             }
                   return make_response(jsonify(responseObject)), 400

                if file:
                    # Save the file to the uploads folder
                    filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                    file.save(filename)
                    
                    new_work_record = WorkRecord(
                        work_order_id=data['work_order_id'],
                        work_date=datetime.strptime(data['work_date'], '%Y-%m-%dT%H:%M:%S.%fZ'),
                        work_done_tons=data['work_done_tons'],
                        proof_of_work_file_path=filename,
                        is_verified=False
                    )
                    app.logger.info(new_work_record.work_order_id)
                    db.session.add(new_work_record)
                    db.session.commit()
                    responseObject = {
                        'status': 'success',
                        'message': 'Work Record uploaded successfully'
                    }
                    user_activity = UserActivity(self.current_user_id, f'Work Record for work Order {new_work_record.work_order_id} Updated','POST',)
                    user_activity.log_activity()
                    return make_response(jsonify(responseObject)), 201
        except Exception as e:
            app.logger.error('property record commit error ' + str(e))
            db.session.rollback()  # Rollback the transaction in case of an error
            responseObject = {
                'status': 'fail',
                'message': 'Error occurred while adding property'
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
                work_record_id = data.get('record_id')
                if not work_record_id:
                    responseObject = {
                                'status': 'fail',
                                'message': 'Invalid Request, please provide necessary fields'
                                    }
                    return make_response(jsonify(responseObject)), 400
                if work_record_id and self.is_admin:
                    work_record = WorkRecord.query.filter_by(record_id=work_record_id).first()
                    if not work_record:
                        responseObject = {
                                'status': 'error',
                                'message': 'Record not found'
                                    }
                        return make_response(jsonify(responseObject)), 404
                    if 'is_verified' in data:
                        is_verified = data.get('is_verified') == '1'
                        work_record.is_verified = is_verified
                        db.session.commit()
                        if is_verified:
                            work_order = WorkOrder.query.filter_by(work_order_id=work_record.work_order_id).first()
                            property = Property.query.filter_by(property_id=work_order.property_id).first()
                            user = User.query.filter_by(user_id=work_order.user_id).first()
                            print(user.role)
                            pay_rate = property.cost_to_labour if user.role == 'labour' else property.cost_to_driver
                            if work_order:
                                if(data.get('work_done') > 0):
                                # Assuming you have some values to update total_earnings and total_work_done
                                    work_order.total_work_done += data.get('work_done')  
                                    print(work_order.total_work_done)
                                    work_order.total_earnings = (work_order.total_work_done*pay_rate)  # Update with your logic
                                    property.completed_work+= data.get('work_done') if user.role == 'labour' else 0
                                    db.session.commit()
                                else:
                                    if work_order.paid_out is None:
                                        work_order.paid_out = data.get('work_done')
                                    else:
                                        work_order.paid_out += data.get('work_done')
                                    db.session.commit()
                        responseObject = {
                        'status': 'success',
                        'message': f'Work Record {work_record_id} updated successfully'
                        }
                        user_activity = UserActivity(self.current_user_id, f'Work Record {work_record.work_order_id} Updated','PUT',)
                        user_activity.log_activity()
                        return make_response(jsonify(responseObject)), 200
                    else:
                        responseObject = {
                        'status': 'error',
                        'message': f'Missing or invalid is_verified value'
                        }
                        return make_response(jsonify(responseObject)), 400 
        except Exception as e:
            app.logger.error('property record commit error ' + str(e))
            db.session.rollback()  # Rollback the transaction in case of an error
            responseObject = {
                'status': 'fail',
                'message': 'Error occurred while updating work record'
            }
            return make_response(jsonify(responseObject)), 500

          
work_records_view = WorkRecordAPI.as_view('work_record_api')

@work_record_blueprint.route('/work_records/<path:filename>')
def serve_work_record(filename):
    directory, filename = os.path.split(filename)
    return send_from_directory(directory, filename)

work_record_blueprint.add_url_rule(
    '/api/work_record',
    view_func=work_records_view,
    methods=['POST']
)

work_record_blueprint.add_url_rule(
    '/api/work_record',
    view_func=work_records_view,
    methods=['PUT']
)
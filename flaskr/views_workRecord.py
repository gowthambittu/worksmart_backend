from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView
from . import bcrypt, db,app
from flaskr.models import User,BlacklistToken,Property,WorkOrder,WorkRecord
from datetime import datetime
from flaskr.schemas import PropertySchema, WorkOrderSchema
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
                        work_date=datetime.strptime(data['work_date'], '%Y-%m-%dT%H:%M:%S.%fZ')
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
                    return make_response(jsonify(responseObject)), 201
        except Exception as e:
            app.logger.error('property record commit error ' + str(e))
            db.session.rollback()  # Rollback the transaction in case of an error
            responseObject = {
                'status': 'fail',
                'message': 'Error occurred while adding property'
            }
            return make_response(jsonify(responseObject)), 500
    

    
            
work_records_view = WorkRecordAPI.as_view('work_record_api')

work_record_blueprint.add_url_rule(
    '/api/work_record',
    view_func=work_records_view,
    methods=['POST']
)
from flask import Blueprint, request, make_response, jsonify, g
from flask.views import MethodView
from . import bcrypt, db,app
from flaskr.models import OutboundRecord, User, UserActivity
from datetime import datetime
from flaskr.schemas import OutboundRecordSchema
from flask import send_from_directory
import os
import cloudinary.uploader

outbound_record_blueprint = Blueprint("outbound_record", __name__)


def _log_exception(event_name, exc):
    app.logger.exception(
        event_name,
        extra={"request_id": getattr(g, "request_id", None)},
    )

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
            _log_exception("outbound_init_failed", e)

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
            weight_in_kgs_raw = data.get('weight_in_kgs')
            weight_in_tons_raw = data.get('weight_in_tons')
            if (not weight_in_kgs_raw and not weight_in_tons_raw) or not data.get('truck_number'):
                   responseObject = {
                        'status': 'fail',
                        'message': 'Invalid Request, please provide necessary fields'
                             }
                   return make_response(jsonify(responseObject)), 400
            try:
                weight_in_kgs = (
                    float(weight_in_kgs_raw)
                    if weight_in_kgs_raw not in (None, '')
                    else float(weight_in_tons_raw) * 1000.0
                )
            except (TypeError, ValueError):
                return make_response(jsonify({'status': 'fail', 'message': 'Invalid weight_in_kgs'})), 400
            filename = None
            if file:
                upload_result = cloudinary.uploader.upload(
                    file,
                    folder="worksmart/outbound_records",
                    resource_type="auto"
                )
                filename = upload_result['secure_url']

            new_outbound_record = OutboundRecord(
                weight_in_kgs=weight_in_kgs,
                weight_in_tons=weight_in_kgs / 1000.0,
                truck_number=data['truck_number'],
                receipt_proof=filename,
                created_id=self.current_user_id,
                truck_date=data.get('truck_date'),
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
            _log_exception("outbound_create_failed", e)
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
            _log_exception("outbound_update_failed", e)
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
                    responseObject = {
                                        'status': 'success',
                                        'data': outbound_records
                                    }
                return make_response(jsonify(responseObject)), 200
        except Exception as e:
            _log_exception("outbound_get_failed", e)
            responseObject = {
                'status': 'fail',
                'message': 'Error occurred while fetching properties'
            }
            return make_response(jsonify(responseObject)), 500

    def patch(self, outbound_id):
        try:
            if self.is_token_error or not self.is_admin:
                return make_response(jsonify({
                    'status': 'fail',
                    'message': 'Unauthorized or Invalid token.'
                })), 403

            outbound_record = OutboundRecord.query.filter_by(outbound_id=outbound_id).first()
            if not outbound_record:
                return make_response(jsonify({
                    'status': 'fail',
                    'message': 'Outbound record not found'
                })), 404

            data = request.get_json() or {}
            changed = False

            if 'truck_number' in data and data.get('truck_number') is not None:
                outbound_record.truck_number = str(data.get('truck_number')).strip()
                changed = True

            if 'truck_date' in data and data.get('truck_date'):
                try:
                    outbound_record.truck_date = datetime.fromisoformat(str(data.get('truck_date')).replace('Z', '+00:00'))
                except ValueError:
                    return make_response(jsonify({
                        'status': 'fail',
                        'message': 'Invalid truck_date format'
                    })), 400
                changed = True

            if 'weight_in_kgs' in data or 'weight_in_tons' in data:
                try:
                    weight_in_kgs = (
                        float(data.get('weight_in_kgs'))
                        if data.get('weight_in_kgs') is not None
                        else float(data.get('weight_in_tons')) * 1000.0
                    )
                except (TypeError, ValueError):
                    return make_response(jsonify({
                        'status': 'fail',
                        'message': 'Invalid weight value'
                    })), 400
                outbound_record.weight_in_kgs = weight_in_kgs
                outbound_record.weight_in_tons = weight_in_kgs / 1000.0
                changed = True

            if not changed:
                return make_response(jsonify({
                    'status': 'success',
                    'message': 'No changes provided.'
                })), 200

            outbound_record.update_date = datetime.now()
            db.session.commit()
            user_activity = UserActivity(
                self.current_user_id,
                f'Outbound Record {outbound_record.truck_number} Edited',
                'PATCH',
            )
            user_activity.log_activity()
            return make_response(jsonify({
                'status': 'success',
                'message': 'Outbound record updated successfully'
            })), 200
        except Exception as e:
            _log_exception("outbound_patch_failed", e)
            db.session.rollback()
            return make_response(jsonify({
                'status': 'fail',
                'message': 'Error occurred while updating outbound record'
            })), 500

    def delete(self, outbound_id):
        try:
            if self.is_token_error or not self.is_admin:
                return make_response(jsonify({
                    'status': 'fail',
                    'message': 'Unauthorized or Invalid token.'
                })), 403

            outbound_record = OutboundRecord.query.filter_by(outbound_id=outbound_id).first()
            if not outbound_record:
                return make_response(jsonify({
                    'status': 'fail',
                    'message': 'Outbound record not found'
                })), 404

            truck_number = outbound_record.truck_number
            db.session.delete(outbound_record)
            db.session.commit()
            user_activity = UserActivity(
                self.current_user_id,
                f'Outbound Record {truck_number} Deleted',
                'DELETE',
            )
            user_activity.log_activity()
            return make_response(jsonify({
                'status': 'success',
                'message': 'Outbound record deleted successfully'
            })), 200
        except Exception as e:
            _log_exception("outbound_delete_failed", e)
            db.session.rollback()
            return make_response(jsonify({
                'status': 'fail',
                'message': 'Error occurred while deleting outbound record'
            })), 500
            

        
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

outbound_record_blueprint.add_url_rule(
    '/api/outbound_record/<int:outbound_id>',
    view_func=outbound_record_view,
    methods=['PATCH', 'DELETE']
    )

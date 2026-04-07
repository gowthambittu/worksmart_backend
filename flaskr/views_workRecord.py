from flask import Blueprint, request, make_response, jsonify, g
from flask.views import MethodView
from . import db, app
from flaskr.models import User, Property, WorkOrder, WorkRecord, UserActivity, WorkRecordAudit
from datetime import datetime
from flask import send_from_directory
import os
import json
import cloudinary.uploader

work_record_blueprint = Blueprint("work_record", __name__)


def _log_exception(event_name, exc):
    app.logger.exception(
        event_name,
        extra={"request_id": getattr(g, "request_id", None)},
    )


def _parse_work_date(value):
    if not value:
        raise ValueError('work_date is required')
    for fmt in ('%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%d'):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise ValueError('Invalid work_date format. Expected YYYY-MM-DD or ISO timestamp.')


def _record_snapshot(record):
    if not record:
        return None
    return {
        'record_id': record.record_id,
        'work_order_id': record.work_order_id,
        'work_date': record.work_date.isoformat() if record.work_date else None,
        'work_done_tons': float(record.work_done_tons) if record.work_done_tons is not None else None,
        'proof_of_work_file_path': record.proof_of_work_file_path,
        'is_verified': bool(record.is_verified),
        'created_at': record.created_at.isoformat() if record.created_at else None,
        'update_date': record.update_date.isoformat() if record.update_date else None,
    }


def _add_work_record_audit(record_id, action, reason, before_payload, after_payload, acted_by_user_id):
    audit = WorkRecordAudit(
        record_id=record_id,
        action=action,
        reason=reason,
        before_payload=json.dumps(before_payload) if before_payload is not None else None,
        after_payload=json.dumps(after_payload) if after_payload is not None else None,
        acted_by_user_id=acted_by_user_id,
        acted_at=datetime.now(),
    )
    db.session.add(audit)


def _recompute_property_metrics(property_id):
    property_record = Property.query.filter_by(property_id=property_id).first()
    if not property_record:
        return

    work_orders = WorkOrder.query.filter_by(property_id=property_id).all()
    property_completed_work = 0.0

    for work_order in work_orders:
        verified_records = WorkRecord.query.filter_by(
            work_order_id=work_order.work_order_id,
            is_verified=True,
        ).all()

        total_work_done = 0.0
        paid_out = 0.0
        for record in verified_records:
            tons = float(record.work_done_tons or 0)
            if tons > 0:
                total_work_done += tons
            else:
                paid_out += tons

        user = User.query.filter_by(user_id=work_order.user_id).first()
        if user and user.role == 'labour':
            pay_rate = (
                work_order.cost_to_labour
                if work_order.cost_to_labour is not None
                else property_record.cost_to_labour
            )
        else:
            pay_rate = (
                work_order.cost_to_driver
                if work_order.cost_to_driver is not None
                else property_record.cost_to_driver
            )

        work_order.total_work_done = round(total_work_done, 2)
        work_order.total_earnings = round(float(work_order.total_work_done or 0) * float(pay_rate or 0), 2)
        work_order.paid_out = round(paid_out, 2) if paid_out != 0 else None
        work_order.update_date = datetime.now()

        property_completed_work += total_work_done

    property_record.completed_work = round(property_completed_work, 2)

    all_work_orders_completed = len(work_orders) > 0 and all(bool(wo.is_completed) for wo in work_orders)

    if all_work_orders_completed and float(property_record.land_area_acres or 0) > 0:
        property_record.avg_yield_per_acre = round(
            float(property_record.completed_work or 0) / float(property_record.land_area_acres),
            2,
        )
    else:
        property_record.avg_yield_per_acre = None


def _normalize_text(value):
    if value is None:
        return ''
    return str(value).strip()


class WorkRecordAPI(MethodView):
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
            _log_exception("work_record_init_failed", e)

    def post(self):
        try:
            if self.is_token_error:
                responseObject = {
                    'status': 'fail',
                    'message': 'Invalid token. Please log in again '
                }
                return make_response(jsonify(responseObject)), 403

            data = request.form
            file = request.files.get('proof_of_work')
            if not data.get('work_done_tons') or not data.get('work_order_id') or not data.get('work_date'):
                responseObject = {
                    'status': 'fail',
                    'message': 'Invalid Request, please provide necessary fields'
                }
                return make_response(jsonify(responseObject)), 400

            work_order = WorkOrder.query.filter_by(work_order_id=data.get('work_order_id')).first()
            if not work_order:
                return make_response(jsonify({'status': 'fail', 'message': 'Work order not found'})), 404

            correction_reason = _normalize_text(data.get('reason'))
            if work_order.is_completed and not correction_reason:
                return make_response(jsonify({
                    'status': 'fail',
                    'message': 'Reason is required when adding record to a completed work order.'
                })), 400

            filename = None
            if file:
                upload_result = cloudinary.uploader.upload(
                    file,
                    folder="worksmart/work_records",
                    resource_type="auto"
                )
                filename = upload_result['secure_url']

            new_work_record = WorkRecord(
                work_order_id=data['work_order_id'],
                work_date=_parse_work_date(data['work_date']),
                work_done_tons=data['work_done_tons'],
                proof_of_work_file_path=filename,
                is_verified=False
            )
            db.session.add(new_work_record)

            if work_order.is_completed:
                work_order.is_completed = False
                work_order.update_date = datetime.now()
                reopen_desc = (
                    f'Work order {work_order.work_order_id} reopened due to new record.'
                    f' Reason: {correction_reason}'
                )
                db.session.add(
                    UserActivity(
                        self.current_user_id,
                        reopen_desc,
                        'work_order_reopened_due_to_new_record',
                    )
                )
                # Recompute so property avg_yield_per_acre/state reflects reopen.
                _recompute_property_metrics(work_order.property_id)
            db.session.commit()

            responseObject = {
                'status': 'success',
                'message': 'Work Record uploaded successfully'
            }
            user_activity = UserActivity(
                self.current_user_id,
                f'Work Record for work Order {new_work_record.work_order_id} Updated',
                'POST',
            )
            user_activity.log_activity()
            return make_response(jsonify(responseObject)), 201
        except ValueError as e:
            db.session.rollback()
            return make_response(jsonify({'status': 'fail', 'message': str(e)})), 400
        except Exception as e:
            _log_exception("work_record_create_failed", e)
            db.session.rollback()
            responseObject = {
                'status': 'fail',
                'message': 'Error occurred while adding property'
            }
            return make_response(jsonify(responseObject)), 500

    def patch(self, record_id):
        try:
            if self.is_token_error:
                return make_response(jsonify({'status': 'fail', 'message': 'Invalid token. Please log in again '})), 403

            work_record = WorkRecord.query.filter_by(record_id=record_id).first()
            if not work_record:
                return make_response(jsonify({'status': 'fail', 'message': 'Record not found'})), 404

            work_order = WorkOrder.query.filter_by(work_order_id=work_record.work_order_id).first()
            if not work_order:
                return make_response(jsonify({'status': 'fail', 'message': 'Work order not found'})), 404

            is_owner = (work_order.user_id == self.current_user_id)
            if not self.is_admin and not is_owner:
                return make_response(jsonify({'status': 'fail', 'message': 'Not authorized to modify this record'})), 403

            if work_record.is_verified and not self.is_admin:
                return make_response(jsonify({'status': 'fail', 'message': 'Only admin can edit approved records'})), 403

            data = request.get_json() or {}
            reason = (data.get('reason') or '').strip()
            if not reason:
                return make_response(jsonify({'status': 'fail', 'message': 'Reason is required for record correction'})), 400

            before_payload = _record_snapshot(work_record)

            if 'work_done_tons' in data:
                try:
                    work_record.work_done_tons = float(data.get('work_done_tons'))
                except (TypeError, ValueError):
                    return make_response(jsonify({'status': 'fail', 'message': 'Invalid work_done_tons'})), 400

            if 'work_date' in data and data.get('work_date'):
                work_record.work_date = _parse_work_date(data.get('work_date'))

            work_record.update_date = datetime.now()
            after_payload = _record_snapshot(work_record)

            _add_work_record_audit(
                record_id=work_record.record_id,
                action='edit',
                reason=reason,
                before_payload=before_payload,
                after_payload=after_payload,
                acted_by_user_id=self.current_user_id,
            )
            _recompute_property_metrics(work_order.property_id)

            db.session.commit()

            user_activity = UserActivity(
                self.current_user_id,
                f'Work Record {work_record.record_id} corrected',
                'PATCH',
            )
            user_activity.log_activity()

            return make_response(jsonify({'status': 'success', 'message': 'Work record updated successfully'})), 200
        except ValueError as e:
            db.session.rollback()
            return make_response(jsonify({'status': 'fail', 'message': str(e)})), 400
        except Exception as e:
            _log_exception("work_record_patch_failed", e)
            db.session.rollback()
            return make_response(jsonify({'status': 'fail', 'message': 'Error occurred while patching work record'})), 500

    def delete(self, record_id):
        try:
            if self.is_token_error:
                return make_response(jsonify({'status': 'fail', 'message': 'Invalid token. Please log in again '})), 403

            work_record = WorkRecord.query.filter_by(record_id=record_id).first()
            if not work_record:
                return make_response(jsonify({'status': 'fail', 'message': 'Record not found'})), 404

            work_order = WorkOrder.query.filter_by(work_order_id=work_record.work_order_id).first()
            if not work_order:
                return make_response(jsonify({'status': 'fail', 'message': 'Work order not found'})), 404

            is_owner = (work_order.user_id == self.current_user_id)
            if not self.is_admin and not is_owner:
                return make_response(jsonify({'status': 'fail', 'message': 'Not authorized to delete this record'})), 403

            if work_record.is_verified and not self.is_admin:
                return make_response(jsonify({'status': 'fail', 'message': 'Only admin can delete approved records'})), 403

            data = request.get_json(silent=True) or {}
            reason = (data.get('reason') or '').strip()
            if not reason:
                return make_response(jsonify({'status': 'fail', 'message': 'Reason is required for record deletion'})), 400

            before_payload = _record_snapshot(work_record)

            _add_work_record_audit(
                record_id=work_record.record_id,
                action='delete',
                reason=reason,
                before_payload=before_payload,
                after_payload=None,
                acted_by_user_id=self.current_user_id,
            )

            db.session.delete(work_record)
            _recompute_property_metrics(work_order.property_id)
            db.session.commit()

            user_activity = UserActivity(self.current_user_id, f'Work Record {record_id} deleted', 'DELETE')
            user_activity.log_activity()
            return make_response(jsonify({'status': 'success', 'message': 'Work record deleted successfully'})), 200
        except Exception as e:
            _log_exception("work_record_delete_failed", e)
            db.session.rollback()
            return make_response(jsonify({'status': 'fail', 'message': 'Error occurred while deleting work record'})), 500

    def put(self):
        try:
            if self.is_token_error:
                responseObject = {
                    'status': 'fail',
                    'message': 'Invalid token. Please log in again '
                }
                return make_response(jsonify(responseObject)), 403

            data = request.get_json() or {}
            work_record_id = data.get('record_id')
            if not work_record_id:
                responseObject = {
                    'status': 'fail',
                    'message': 'Invalid Request, please provide necessary fields'
                }
                return make_response(jsonify(responseObject)), 400

            if not self.is_admin:
                return make_response(jsonify({'status': 'fail', 'message': 'Only admin can verify records'})), 403

            work_record = WorkRecord.query.filter_by(record_id=work_record_id).first()
            if not work_record:
                responseObject = {
                    'status': 'error',
                    'message': 'Record not found'
                }
                return make_response(jsonify(responseObject)), 404

            if 'is_verified' not in data:
                return make_response(jsonify({'status': 'error', 'message': 'Missing or invalid is_verified value'})), 400

            work_order = WorkOrder.query.filter_by(work_order_id=work_record.work_order_id).first()
            if not work_order:
                return make_response(jsonify({'status': 'error', 'message': 'Work order not found'})), 404

            is_verified = str(data.get('is_verified')).lower() in ('1', 'true', 'yes')
            work_record.is_verified = is_verified
            work_record.update_date = datetime.now()

            _recompute_property_metrics(work_order.property_id)
            db.session.commit()

            responseObject = {
                'status': 'success',
                'message': f'Work Record {work_record_id} updated successfully'
            }
            user_activity = UserActivity(self.current_user_id, f'Work Record {work_record.work_order_id} Updated', 'PUT')
            user_activity.log_activity()
            return make_response(jsonify(responseObject)), 200
        except Exception as e:
            _log_exception("work_record_update_failed", e)
            db.session.rollback()
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

work_record_blueprint.add_url_rule(
    '/api/work_record/<int:record_id>',
    view_func=work_records_view,
    methods=['PATCH', 'DELETE']
)

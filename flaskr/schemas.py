from flaskr.models import Property,WorkOrder,WorkRecord,OutboundRecord
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow as ma
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from marshmallow import fields


class PropertySchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Property
    
class WorkOrderSchema(SQLAlchemyAutoSchema):
    property_id = fields.Integer()
    user_id = fields.Integer()
    property_name= fields.String()
    location = fields.String()
    user_full_name = fields.Method('get_user_full_name')
    user_role = fields.Method('get_user_role')
    def get_user_full_name(self, obj):
        return obj.user.full_name
    def get_user_role(self, obj):
        return obj.user.role
    class Meta:
        model = WorkOrder



class WorkRecordSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = WorkRecord

class OutboundRecordSchema(SQLAlchemyAutoSchema):
    created_id = fields.Integer()
    class Meta:
        model = OutboundRecord    
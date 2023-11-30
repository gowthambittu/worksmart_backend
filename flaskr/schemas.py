from flaskr.models import Property,WorkOrder,WorkRecord
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow as ma
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema


class PropertySchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Property
    
class WorkOrderSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = WorkOrder

class WorkRecordSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = WorkRecord
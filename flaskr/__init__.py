import os
import os
from dotenv import load_dotenv
from urllib.parse import quote
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
import logging
from flask_migrate import Migrate



load_dotenv() 

# def create_app(test_config=None):
#     # create and configure the app
app = Flask(__name__)
CORS(app, origins="http://localhost:3000", resources={r"/*": {"origins": "https://smartworkmanagement.com"}})
db_password = quote(os.getenv('MYSQL_PASSWORD'))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI').format(db_password)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.getenv('IMG_FOLDER')
app.config['OUTBOUND_FOLDER'] = os.getenv('OUTBOUND_FOLDER')
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

@app.route('/hello')
def hello():
    return ("Hello World")

# Import and register blueprints, configure other app settings, etc.
from . import views, views_outbound,views_workRecord,views_properties
app.register_blueprint(views.auth_blueprint)
app.register_blueprint(views_properties.property_blueprint)
app.register_blueprint(views_workRecord.work_record_blueprint)
app.register_blueprint(views_outbound.outbound_record_blueprint)
if app.debug:
    # Configure the logger to display debug logs
    app.logger.setLevel(logging.DEBUG)

    # Add a console handler to output the logs to the console
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)

    # Create a formatter to format the log messages
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # Add the handler to the logger
    app.logger.addHandler(handler)
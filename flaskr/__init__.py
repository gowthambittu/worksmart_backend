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
CORS(app)
db_password = quote(os.getenv('MYSQL_PASSWORD'))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI').format(db_password)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.getenv('IMG_FOLDER')
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

@app.route('/hello')
def hello():
    return ("Hello World")

# Import and register blueprints, configure other app settings, etc.
from . import views
from . import views_properties
from . import views_workRecord
app.register_blueprint(views.auth_blueprint)
app.register_blueprint(views_properties.property_blueprint)
app.register_blueprint(views_workRecord.work_record_blueprint)
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
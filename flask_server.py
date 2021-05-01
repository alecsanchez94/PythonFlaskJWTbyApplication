from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_restful import Api
from flask_script import Manager
from flask import Flask
# import celeryServer
from flask_ipinfo import IPInfo
import logging

from flask_sqlalchemy import SQLAlchemy

import celeryServer

app = Flask(__name__)
logging.basicConfig(filename='record.log', level=logging.DEBUG,
                    format=f'%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')
CORS(app, resources={r"/*": {"origins": "*"}})
app.config.from_pyfile('config.py')
celery = celeryServer.make_celery(app)

db = SQLAlchemy(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
api = Api(app)
manager = Manager(app)
ipinfo = IPInfo()



# Initialize Admin Application
from app_admin import models, views

api.init_app(app)
db.init_app(app)

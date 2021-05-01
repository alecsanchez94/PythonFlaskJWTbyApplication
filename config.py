from datetime import datetime, timedelta


#Database connection, currently setup for a mysql database
host = "" #IP or endpoint
port = 3306 #Standard port for mysql database
database = "" #Database name
user = "" #Recommend to use a dedicated account for the application here
passw = ""

conn_string = "mysql+pymysql://{user}:{passw}@{host}:{port}/{database}".format(user=user, passw=passw,
                                                                                       host=host, port=str(port),
                                                                                       database=database)

debug = True
SECRET_KEY = 'PleaseChangeThis'
SQLALCHEMY_DATABASE_URI = conn_string
SQLALCHEMY_TRACK_MODIFICATIONS = False
JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15, seconds=0)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=14)
JWT_SECRET_KEY = "PleaseChangeThis"  # Change this!
CORS_ORIGINS = "*" #Not recommended

MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USE_SSL = False
MAIL_USERNAME = 'youremail@gmail.com'
MAIL_PASSWORD = 'ItsPassword'

SECURITY_PASSWORD_SALT = 'ARandomStringOfCharacters'
MAIL_DEFAULT_SENDER = MAIL_USERNAME

CELERY_BROKER_URL='redis://localhost:6379'
CELERY_RESULT_BACKEND='redis://localhost:6379'
CELERY_ACCEPT_CONTENT = ['application/json']
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TASK_SERIALIZER = 'json'
CELERY_TASK_TRACK_STARTED = True

#Change to your IP, or domain name


#Change according to your hosting practices
FRONTEND_PORT = 3000 #Default React Port
FRONTEND_SERVERNAME = '' #An IP
FRONTEND = "{}:{}".format(FRONTEND_SERVERNAME, FRONTEND_PORT)

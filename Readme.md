# PythonFlaskJWTbyApplication

<h2>Python Flask Server</h2>
<p>With JWT Authentication, User Signup, and Structured by App for scalability</p>
<p>Includes Celery and Redis for background task queue</p>

## Setup
```console_window
To run from source, install Python 3.7+ 64 bit

Install pre-requisites and start the interface
$ pip install -r requirements.txt
```

## A few things before getting started
```console_window
config.py
Setup database connection
Change SECRET_KEY, JWT_SECRET_KEY, SECURITY_PASSWORD_SALT
Setup Mail variables, recommend to use gmail, its free and easy
Setup FRONTEND variables, currently setup for IP:PORT connection, can easily be changed to a single string variable for a domain. This is used to create URLs for the frontend.

```
## Initialize Redis and Load the Celery
```console_window
Initialize Redis
$ cd redis && redis-server

Make the Celery in another terminal
$ celery -A flask_server.celery worker -E -l info --pool=solo

```

## Initialize the flask server
```console_window
Environment variables are located in .env and are loaded through python-dotenv, installed through requirements.txt
See config.py for server settings
$ flask run

```

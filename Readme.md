# PythonFlaskJWTbyApplication

<h2>Python Flask Server</h2>
<p>With JWT Authentication, User Signup, and Structured by App for scalability</p>
<p>Includes Celery and Redis for background task queue</p>

## Setup
```console_window
Developed using Windows 10 64bit and Python 3.7

Install pre-requisites and start the interface
$ pip install -r requirements.txt
```

## A few things before getting started

<p>Open config.py</p>

  <li>Setup database connection</li>
  <li>Change SECRET_KEY, JWT_SECRET_KEY, SECURITY_PASSWORD_SALT</li>
  <li>Setup Mail variables, recommend to use gmail, its free and easy</li>
  <li>Setup FRONTEND variables, currently setup for IP:PORT connection, can easily be changed to a single string variable for a domain. This is used to create URLs for the frontend.</li>
 ```console_window

$ python update_db.py

```
  
## Update the database with defined models


## Initialize Redis and Load the Celery
```console_window
Completely optional with the current build, there are no tasks setup for the Celery, but it wouldn't be too hard to do at this point. (Example tasks coming soon!)

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

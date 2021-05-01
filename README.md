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

## Initialize Redis and Load the Celery
```console_window
Initialize Redis
$ cd redis && redis-server

Make the Celery in another terminal
$ celery -A flask_server.celery worker -E -l info --pool=solo

```

## Initialize the flask server
```console_window

$ flask run

```

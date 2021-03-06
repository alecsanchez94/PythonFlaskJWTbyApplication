# PythonFlaskJWTbyApplication

<h2>Python Flask Server</h2>
<p>With JWT Authentication, User Signup, and Structured by App for scalability</p>
<p>Setup for backend functionality at this point only</p>
<p>Includes Celery and Redis for background task queue</p>

<h2> What is this? </h2>
<p>A backend server for applications. Currently configured to serve as an API for frontends.</p>

<h2> Who is it for? </h2>
<p>Application, or even game developers looking to create their own backend API on their terms.</p>
<p>There are other solutions such as Django, but I personally found this to be very heavy weight, in that you have to do things the Django way. I enjoy making my own tools and ensuring my applications do exactly what I want them to do, I found that Flask is incredibly flexible for organization and scalability.</p>

 [Learn more about Authentication using this backend](Authentication.md)

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
  

  
## Update the database with defined models
 ```console_window
At this point, its very important the database variables are setup and working, checkout the jupyter notebook to test your mysql connection
$ python update_db.py

```

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

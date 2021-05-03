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

<h2>What is JWT Authentication?</h2>
<p>JSON (Javascript Open Notation) Web Token</p>
<p>Client logs in to application, Server responds with refresh and activation tokens (It does not have to be this way, you can do it however you want, maybe you only want the refresh token, I recommend you do your research on security). The tokens are stored on the client side, and are used for further API calls that required the tokens for authentication. I'm going to assume you're using some sort of Javascript framework for your frontend, please see below for some API examples with Javascript where we handle authentication and tokens. In the below Javascript examples, we'll be using the library Axios for our API calls, Axios has feature called axiosinterceptors which allows us to do things before and after each API call.</p>
<p>The below function does not make use of axiosinterceptors as it does not need to, we do not need to send tokens along with the login request</p>
  
 ```console_window
 Javascript login example
 
 export const login = (email, password) => async => {
    const body = {
        "email": email,
        "password": password
    }

    try {
        
        const res = await axios.post(`${process.env.REACT_APP_API_URL}/auth/jwt/create/`, body);
        if (res.data.code !== 'token_not_valid') {
            axiosInstance.defaults.headers['Authorization'] = "Bearer " + res.data.access_token;
            localStorage.setItem('access_token', res.data.access_token);
            localStorage.setItem('refresh_token', res.data.refresh_token);
        }
    } catch (err) {
        console.log(err)
    }
};
 ```
 
 <p>Tokens expire after a defined amount of time, the refresh token will last 14 days (Generally accepted), while the access token lasts 15 minutes. The Access token is used to for protected API calls with "jwt_required()". </p>

 

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

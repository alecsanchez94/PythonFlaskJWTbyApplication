
<h2>What is JWT Authentication?</h2>
<p>JSON (Javascript Open Notation) Web Token</p>
<p>Client logs in to application, Server responds with refresh and activation tokens (It does not have to be this way, you can do it however you want, maybe you only want the refresh token, I recommend you do your research on security). The tokens are stored on the client side, and are used for further API calls that required the tokens for authentication.</p> 

<p>I'm going to assume you're using some sort of Javascript framework for your frontend, please see below for some API examples with Javascript where we handle authentication and tokens. In the below Javascript examples, we'll be using the library Axios for our API calls, Axios has feature called interceptors which allows us to do things before and after each API call.</p>
<p>The below function does not make use of interceptors as it does not need to, we do not need to send tokens along with the login request. Another important note, with this example we are storing the tokens using "localstorage", I believe it is currently recommended to store these tokens using cookies, please stay tuned for a future update.</p>
  
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


```console_window


const axiosInstance = axios.create({
    baseURL: baseURL,
    timeout: 5000,
    headers: {
        'Authorization': localStorage.getItem('access_token') ? "Bearer " + localStorage.getItem('access_token') : null,
    }
});
```
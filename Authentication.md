
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
 <p>See config.py for token settings.</p>
 
 [config.py](config.py)


```console_window
const axiosInstance = axios.create({
    baseURL: baseURL,
    timeout: 5000,
    headers: {
        'Authorization': localStorage.getItem('access_token') ? "Bearer " + localStorage.getItem('access_token') : null,
    }
});
```

<p>Now lets setup interceptors to handle the tokens before and after each request.</p>

```console_window

axiosInstance.interceptors.request.use(function (config) {
    const refreshToken = localStorage.getItem('refresh_token');
    const tokenParts = JSON.parse(atob(refreshToken.split('.')[1]));

    if (Date.now() >= tokenParts.exp * 1000) {
        axiosInstance.defaults.headers['Authorization'] = "Bearer " + refreshToken;
        return axiosInstance
            .post('/auth/jwt/refresh/')
            .then((response) => {

                localStorage.setItem('access_token', response.data.access_token);
                axiosInstance.defaults.headers['Authorization'] = "Bearer " + response.data.access_token;
            })

    }

    return config;
}, function (error) {
    return Promise.reject(error);
});


axiosInstance.interceptors.response.use(
    response => response,
    error => {
        const originalRequest = error.config;
        const status = error.response ? error.response.status : null


        // Prevent infinite loops early
        if (status === 401 && originalRequest.url === '/auth/jwt/refresh/') {
            console.log("Preventing infinite loop")
            return Promise.reject(error);
        }


        if (error.response.data.err === "Token has expired" &&
            status === 401 &&
            error.response.statusText === "UNAUTHORIZED") {
            const refreshToken = localStorage.getItem('refresh_token');
            if (refreshToken) {
                const tokenParts = JSON.parse(atob(refreshToken.split('.')[1]));
                const now = Math.ceil(Date.now() / 1000);

                if (tokenParts.exp > now) {
                    axiosInstance.defaults.headers['Authorization'] = "Bearer " + refreshToken;

                    return axiosInstance
                        .post('/auth/jwt/refresh/')
                        .then((response) => {
                            localStorage.setItem('access_token', response.data.access_token);
                            axiosInstance.defaults.headers['Authorization'] = "Bearer " + response.data.access_token;
                            originalRequest.headers['Authorization'] = "Bearer " + response.data.access_token;
                            return axiosInstance(originalRequest);
                        })
                        .catch(err => {

                            console.log("Caught Error in axios interceptor")
                            console.log(err.message)
                            console.log(err.response.data)
                        });
                } else {
                    console.log("Refresh token is expired", tokenParts.exp, now);
                }
            } else {
                console.log("Refresh token not available.")
            }
        }

        console.log("Exiting interceptor")
        // specific error handling done elsewhere
        return Promise.reject(error);
    }
);
```

<p>The hard work has been taken care of. Now we can use the AxiosInstance to make API calls which will automatically handle our expired or soon to be expiring tokens.</p>

```console_window

const API_FetchAllRoles = async () => {

    const res = await axiosInstance.get(`${baseURL}/api/admin/roles/`)
    const result = res.data
    const availRoles = []

    result.map((e) => {
        const tstring = user.roles.toString().toUpperCase()
        if (tstring.indexOf(e.toUpperCase()) === -1) {
            availRoles.push(e)
        }
    })
    //Use some callback here to set data with availRoles
    //seData(availRoles)
}

```

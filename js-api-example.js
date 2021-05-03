import axios from 'axios'

const baseURL = `backend.endpont`;

const axiosInstance = axios.create({
    baseURL: baseURL,
    timeout: 5000,
    headers: {
        'Authorization': localStorage.getItem('access_token') ? "Bearer " + localStorage.getItem('access_token') : null,
    }
});


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


export const login = async (email, password) => {
    const body = {
        "email": email,
        "password": password
    }

    try {

        const res = await axios.post(`${baseURL}/auth/jwt/create/`, body);
        if (res.data.code !== 'token_not_valid') {
            axiosInstance.defaults.headers['Authorization'] = "Bearer " + res.data.access_token;
            localStorage.setItem('access_token', res.data.access_token);
            localStorage.setItem('refresh_token', res.data.refresh_token);
        }
    } catch (err) {
        console.log(err)
    }
};


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
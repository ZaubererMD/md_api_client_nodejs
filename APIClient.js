// ---------------------------------------------------------------------------------
// IMPORTS
// ---------------------------------------------------------------------------------
const fetch = require('node-fetch');
const crypto = require('crypto');
const { URLSearchParams } = require('url');

/**
 * Client for easy communication with an md_api_server
 */
class APIClient {
    /**
     * @typedef {Object} APIClientConfig
     * @property {string} url The URL of the md_api_server to connect to
     */
    /**
     * Creates a new API-client
     * @param {APIClientConfig} config 
     */
    constructor(config) {
        this.config = config;
        this.session = null;
        this.keepAliveInterval = null;
    }

    /**
     * @typedef {Object} CallData
     * @property {string} method The method to call
     * @property {Object} [data] The parameters to pass to the method
     * @property {function ({Object}) => void} [callback] Only used in multicalls: A callback-function that is called when this call executes successfully
     * @property {function ({Object}) => void} [errorCallback] Only used in multicalls: A callback-function that is called when this call executes with an error
     * @property {boolean} [breaking] Only used in multicalls: If this is set to true, the execution of further calls after this one is skipped in case this call fails
     */
    /**
     * Calls a method on the API-Server
     * @param {CallData} callData Properties of the call to execute
     * @returns {Promise} A promise that is resolved with the Response-Data when the API has responded
     */
    call(callData) {
        return new Promise((resolve, reject) => {
            // Prepare POST-body
            const params = new URLSearchParams();
            if(typeof(callData.data) === 'object') {
                for (let prop in callData.data) {
                    if (Object.prototype.hasOwnProperty.call(callData.data, prop)) {
                        params.append(prop, callData.data[prop]);
                    }
                }
            }
            // automatically append the session-token if this client is already logged in
            if(this.session !== null && (typeof(callData.data) !== 'object' || typeof(callData.data.token) === 'undefined')) {
                params.append('token', this.session.token);
            }

            // send data to the API
            let methodURL = this.config.url + '/' + callData.method;
            fetch(methodURL, {
                method : 'POST',
                body : params
            })
            .then(res => res.json())
            .then((response) => {
                // verify whether the method was executed successfully
                if(response.success) {
                    resolve(response.data);
                } else {
                    reject(response.msg);
                }
            })
            .catch((error) => {
                reject(error);
            });
        });
    }

    /**
     * Login to the API and store the session-token in this APIClient-Instance for further calls.
     * It is recommended to store hashed versions of passwords in your application only and feed those into this method.
     * If you want to login with unhashed password you can do so by setting passwordIsHashed to false
     * @param {string} username The username to use for the login
     * @param {string} password The password of the user-account, or preferably the hashed version of it
     * @param {boolean} [passwordIsHashed=true] If this is set to false the password-hash will be created on the fly
     * @returns {Promise} A Promise that is resolved with the session-data after the login was successful
     */
    login(username, password, passwordIsHashed=true) {
        console.log('Getting Login-Token from API...');
        return this.call({
            method : 'session/request_login_token'
        }).then((response) => {
            // If the password is already hashed continue
            if(passwordIsHashed) {
                return response;
            } else {
                // create password-hash on the fly
                let nameSalt = this.sha256(username.toUpperCase());
                let passwordHash = this.sha256(nameSalt, password);
                password = passwordHash;
                return response;
            }
        }).then((response) => {
            // Create a hash of the password-hash and salt it with the login-token
            return this.sha256(password, response.token);
        }).then((loginHash) => {
            console.log('Logging in to API...');
            return this.call({
                method : 'session/login',
                data : {
                    username : username,
                    password_hash : loginHash
                }
            });
        }).then((data) => {
            console.log('Login Successful!');
            // Store session details
            this.session = data.session;
            return this.session;
        });
    }

    /**
     * Logout from the API
     * @returns {Promise} A Promise that is resolved when the logout was successful
     */
    logout() {
        return this.call({
            method : 'session/logout'
        });
    }

    /**
     * Starts an internal interval that calls /sesseion/keep_alive every 30 minutes,
     * so the API server does not kill the session.
     */
    startKeepAlive() {
        this.keepAliveInterval = setInterval(() => {
            this.call({
                method : 'session/keep_alive'
            }).then(() => {
                //console.log('Session has been refreshed');
            });
        }, 30*60*1000);
    }

    /**
     * Stops the interval that keeps the session alive
     */
    stopKeepAlive() {
        clearInterval(this.keepAliveInterval);
    }

    /**
     * Executes multiple API-methods in one request to the API
     * You must provide callback-functions for these calls, since there is not way to resolve a Promise for every single one.
     * You can also set the breaking Property in calls, which will stop the execution of further calls if one with the breaking-flag fails.
     * @param {CallData[]} calls The calls to execute
     * @returns {Promise} A Promise that is resolved when the multicall finishes
     */
    multicall(calls) {
        // Encode individual call data for the multicall-method
        let multicallData = { calls : [] };
        calls.forEach((call) => {
            let callData = call.data || {};
            callData.method = call.method;
            if(typeof(call.breaking) === 'boolean') {
                callData.breaking = call.breaking;
            }
            multicallData.calls.push(callData);
        });

        let multiCallDataJSON = JSON.stringify(multicallData);

        // Run the multicall-method
        return new Promise((resolve, reject) => {
            this.call({
                method : 'multicall/multicall',
                data : {
                    content : multiCallDataJSON
                }
            }).then((multicallResponseData) => {

                // Call individual callback-methods
                for(let i in multicallResponseData.responses) {
                    calls[i].response = multicallResponseData.responses[i];
                    if(calls[i].response.success) {
                        calls[i].callback(calls[i].response.data);
                    } else {
                        calls[i].errorCallback(calls[i].response);
                    }
                }

                resolve(multicallResponseData);

            }).catch((error) => {
                reject(error);
            });
        });
    }

    /**
     * Pass any number of arguments into this function to calculate the SHA256 hash of their concatenation
     * @param  {...string} values Values to calculate the SHA256 Hash for
     * @returns {string} SHA256 hash of the given values
     */
    sha256(...values) {
        let value = values.join('');
        return crypto.createHash('sha256').update(value).digest('hex');
    }
};

module.exports = APIClient;
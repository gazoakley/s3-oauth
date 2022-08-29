'use strict';

const AWS = require('aws-sdk');
const cookie = require('cookie');
const crypto = require('crypto');
const https = require('https');
const jwt = require('jsonwebtoken');
const querystring = require('querystring');

const SSM_PARAMETERS_REGION = 'us-east-1';
const SSM_PARAMETER_NAMES = {
    JWT_SECRET: '${ssm_param_name_jwt_secret}',

    OAUTH_CLIENT_ID: '${ssm_param_name_oauth_client_id}',
    OAUTH_CLIENT_SECRET: '${ssm_param_name_oauth_client_secret}',
    OAUTH_DOMAIN: '${ssm_param_name_oauth_domain}',

    AUTH_COOKIE_NAME: '${ssm_param_name_auth_cookie_name}',
    AUTH_COOKIE_TTL_SEC: '${ssm_param_name_auth_cookie_ttl_sec}'
};

const PARAMETERS = {
    JWT_SECRET: null,

    OAUTH_CLIENT_ID: null,
    OAUTH_CLIENT_SECRET: null,
    OAUTH_DOMAIN: null,
    OAUTH_TIMEOUT_MS: 5000,

    AUTH_COOKIE_NAME: null,
    AUTH_COOKIE_TTL_SEC: null
};

const LOGIN_ENDPOINT = '/login';
const OAUTH_BASE = '/oauth2';

const UNAUTHORIZED_RESPONSE = {
    status: '401',
    statusDescription: 'OK',
    headers: {
        'content-type': [
            {
                key: 'Content-Type',
                value: 'text/html'
            }
        ],
        'cache-control': [
            {
                key: 'Cache-Control',
                value: 'private'
            }
        ]
    },
    body: '<html><head><title>Unauthorized</title></head><body><h1>401 Unauthorized</h1></body></html>'
};
const LOGIN_RESPONSE = {
    status: '302',
    statusDescription: 'Found',
    headers: {
        location: [
            {
                key: 'Location',
                value: null // Set by generateLoginResponse()
            }
        ],
        'cache-control': [
            {
                key: 'Cache-Control',
                value: 'private'
            }
        ]
    }
};
const LOGIN_SUCCESSFUL_RESPONSE = {
    status: '302',
    statusDescription: 'Found',
    headers: {
        location: [
            {
                key: 'Location',
                value: '/'
            }
        ],
        'cache-control': [
            {
                key: 'Cache-Control',
                value: 'private'
            }
        ],
        'set-cookie': [
            {
                key: 'Set-Cookie',
                value: null // Set by generateLoginSuccessfulResponse()
            }
        ],
    }
};

function getOAuthTokens(authCode, lambdaHost) {
    return new Promise((resolve, _) => {
        const reqOptions = {
            method: 'POST',
            hostname: PARAMETERS.OAUTH_DOMAIN,
            path: `$${OAUTH_BASE}/token`,
            auth: `$${PARAMETERS.OAUTH_CLIENT_ID}:$${PARAMETERS.OAUTH_CLIENT_SECRET}`,
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            timeout: PARAMETERS.OAUTH_TIMEOUT_MS
        };
        const reqPayload = querystring.stringify({
            grant_type: 'authorization_code',
            redirect_uri: `https://$${lambdaHost}$${LOGIN_ENDPOINT}`,
            code: authCode
        });

        console.log(JSON.stringify(reqOptions));
        console.log(JSON.stringify(reqPayload));
        
        const req = https.request(reqOptions, res => {
            if (res.statusCode === 200) {
                let rawData = '';

                res.on('data', chunk => {
                    rawData += chunk;
                });

                res.on('end', () => {
                    const jsonResponse = JSON.parse(rawData);

                    if ('id_token' in jsonResponse) {
                        console.debug('OAuth request succeeded');
                        resolve({idToken: jsonResponse.id_token});
                    } else {
                        console.error('OAuth request failed: unexpected response');
                        resolve(null);
                    }
                });
            } else {
                console.error(`OAuth request failed: server returned $${res.statusCode}`);
                res.resume(); // Response data needs to be consumed manually because there is no data handler in this case
                resolve(null);
            }
        });

        req.on('error', error => {
            console.error(`OAuth request failed: $${error.message}`);
            resolve(null);
        });

        req.write(reqPayload);
        req.end();
    });
}

async function getAuth(requestHeaders) {
    if (requestHeaders.cookie) {
        console.debug(`Found $${requestHeaders.cookie.length} Cookie headers`);

        for (let i = 0; i < requestHeaders.cookie.length; ++i) {
            const cookies = cookie.parse(requestHeaders.cookie[i].value);

            if (PARAMETERS.AUTH_COOKIE_NAME in cookies) {
                console.debug(`Auth cookie found at Cookie header index $${i}`);

                const signedJwt = cookies[PARAMETERS.AUTH_COOKIE_NAME];

                try {
                    const decodedJwt = jwt.verify(signedJwt, PARAMETERS.JWT_SECRET);
                    console.debug(`JWT verified, expires at $${decodedJwt.exp}`);
                    return decodedJwt;
                } catch (err) {
                    console.warn(`JWT verification error: $${err.message}`);
                }
            } else {
                console.debug(`Auth cookie not found at Cookie header index $${i}`);
            }
        }
    } else {
        console.debug('No Cookie headers in request');
    }

    return null;
}

async function generateAuthCookie(oauthTokens) {
    const jwtPayload = {
        idToken: oauthTokens.idToken,
        refreshToken: ''
    };
    const jwtOptions = {
        algorithm: 'HS256',
        expiresIn: parseInt(PARAMETERS.AUTH_COOKIE_TTL_SEC)
    };
    // TODO: add salt
    const signedJwt = jwt.sign(jwtPayload, PARAMETERS.JWT_SECRET, jwtOptions);

    // Secure => Cookie is only sent to the server when a request is made with the https: scheme (except on localhost).
    // HttpOnly => Forbids JavaScript from accessing the cookie, for example, through the Document.cookie property.
    // SameStrict=Lax => Cookies are not sent on normal cross-site subrequests, but are sent when a user is navigating to the origin site.
    return `$${PARAMETERS.AUTH_COOKIE_NAME}=$${signedJwt}; Secure; HttpOnly; SameSite=Lax`;
}

function generateLoginResponse(lambdaHost) {
    const response = LOGIN_RESPONSE;
    const nonce = crypto.randomBytes(32).toString('hex');

    response.headers.location[0].value = `https://$${PARAMETERS.OAUTH_DOMAIN}/$${OAUTH_BASE}/authorize?` +
        `client_id=$${PARAMETERS.OAUTH_CLIENT_ID}` +
        `&nonce=$${nonce}` +
        `&redirect_uri=https://$${lambdaHost}$${LOGIN_ENDPOINT}` +
        `&response_type=code` +
        '&response_mode=query' +
        `&scope=openid` +
        `&state=none`;

    return response;
}

async function generateLoginSuccessfulResponse(oauthTokens) {
    const response = LOGIN_SUCCESSFUL_RESPONSE;

    if (oauthTokens !== null) {
        response.headers['set-cookie'][0].value = await generateAuthCookie(oauthTokens);
    } else {
        delete response.headers['set-cookie'];
    }

    return response;
}

function loadParameters() {
    return new Promise((resolve, reject) => {
        const ssm = new AWS.SSM({region: SSM_PARAMETERS_REGION});
        const params = {
            Names: Object.values(SSM_PARAMETER_NAMES),
            WithDecryption: true
        };

        ssm.getParameters(params, function (err, data) {
            if (err) {
                console.error(`Could not retrieve SSM parameters: $${err.message}`);
                reject(err);
            } else {
                console.debug('Successfully retrieved SSM parameters');

                for (let i = 0; i < data.Parameters.length; ++i) {
                    const ssmParameterName = data.Parameters[i].Name;
                    const parameterName = Object.keys(SSM_PARAMETER_NAMES).find(key => SSM_PARAMETER_NAMES[key] === ssmParameterName);

                    PARAMETERS[parameterName] = data.Parameters[i].Value;
                }

                resolve();
            }
        });
    });
}

exports.handler = async (event, context, callback) => {
    const request = event.Records[0].cf.request;
    const headers = request.headers;
    const lambdaHost = headers.host[0].value;
    const queryParams = querystring.parse(request.querystring);

    console.info(`$${request.method} $${request.uri}` +
        (request.querystring ? `?$${request.querystring}` : ''));

    await loadParameters();

    const verifiedJwt = await getAuth(headers);

    if (verifiedJwt !== null) {
        // TODO: refresh token if it expires soon
        // TODO: revoke JWT if OAuth token was revoked before end of the TTL
        if (request.uri === LOGIN_ENDPOINT) {
            console.info('Already authenticated, redirecting to /index.html');
            callback(null, await generateLoginSuccessfulResponse(null));
        } else {
            console.info('Authenticated, forwarding request');
            callback(null, request);
        }
    } else if (request.uri === LOGIN_ENDPOINT) {
        if ('code' in queryParams) {
            const oauthTokens = await getOAuthTokens(queryParams.code, lambdaHost);

            if (oauthTokens !== null) {
                console.info('Login successful');
                callback(null, await generateLoginSuccessfulResponse(oauthTokens));
            } else {
                console.info('Login failed');
                callback(null, UNAUTHORIZED_RESPONSE);
            }
        } else {
            console.info('No OAuth Auth Code supplied, forwarding to login page');
            callback(null, generateLoginResponse(lambdaHost));
        }
    } else {
        console.info('Not authenticated, redirecting to login page');
        callback(null, generateLoginResponse(lambdaHost));
    }
};

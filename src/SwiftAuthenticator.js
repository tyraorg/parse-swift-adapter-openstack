'use strict';

const EventEmitter = require('events');
const util = require('util');
const request = require('request-promise-native');
const logger = require('winston');

const AUTH_STATE = {
    UNAUTHENTICATED: 0,
    AUTHENTICATED: 1,
    FAILED: 2,
};

const AUTH_EVENT = 'authentication';

function SwiftAuthenticator(options) {
    EventEmitter.call(this);

    logger.info('SwiftAuthenticator():', options);

    this.tenantId = options.tenantId;
    this.authUrl = options.authUrl;
    this.baseUrl = options.baseUrl;
    this.username = options.username;
    this.password = options.password;

    this.authState = AUTH_STATE.UNAUTHENTICATED;
    this.tokenId = null;
    this.authError = null;
    this.isAuthenticating = false;
}

util.inherits(SwiftAuthenticator, EventEmitter);

SwiftAuthenticator.prototype._authenticate = function() {
    if (this.isAuthenticating) {
        return Promise.resolve();
    }

    this.isAuthenticating = true;

    return request({
        method: 'POST',
        uri: this.authUrl,
        headers: {
            'Content-type': 'application/json'
        },
        json: true,
        resolveWithFullResponse: true,
        simple: false,
        body: {
            auth: {
                identity: {
                    methods: [
                        "password"
                    ],
                    password: {
                        user: {
                            domain: {
                                id: "default"
                            },
                            name: this.username,
                            password: this.password
                        }
                    }
                },
                scope: {
                    project: {
                        domain: {
                            id: "default"
                        },
                        name: this.tenantId,
                    }
                }
            }
        }
    })
    .then((response) => {
        if (response.statusCode === 200) {
            logger.info('response: ' + JSON.stringify(response))
            this.tokenId = response.body.access.token.id;
            this.authState = AUTH_STATE.AUTHENTICATED;
            this.authError = null;
            this.emit(AUTH_EVENT);

            logger.info('SwiftAuthenticator._authenticate(): new auth token was created');
        } else {
            this.tokenId = null;
            this.authState = AUTH_STATE.FAILED;
            this.authError = response.statusCode + ' - ' + response.statusMessage;
            this.emit(AUTH_EVENT);

            logger.error('SwiftAuthenticator._authenticate(): auth failed with error %d %s',
                response.statusCode, response.statusMessage);
        }
        this.isAuthenticating = false;
    })
    .catch((err) => {
        this.tokenId = null;
        this.authState = AUTH_STATE.FAILED;
        this.authError = err;
        this.isAuthenticating = false;

        logger.error('SwiftAuthenticator._authenticate() - auth failed', err);
    });
};

SwiftAuthenticator.prototype._validateToken = function() {
    return request({
        method: 'HEAD',
        uri: this.baseUrl,
        headers: {
            'X-Auth-Token': this.tokenId
        },
        resolveWithFullResponse: true,
        simple: false
    })
    .then((response) => {
        if (response.statusCode === 204) {
            return true;
        } else {
            logger.error('SwiftAuthenticator._validateToken(): auth token was invalidated: %d %s',
                response.statusCode, response.statusMessage);
            this.authState = AUTH_STATE.UNAUTHENTICATED;
            this.tokenId = null;
            return false;
        }
    });
};

SwiftAuthenticator.prototype.authenticate = function() {

    const waitForAuthentication = () => {
        this._authenticate();

        return new Promise((resolve, reject) => {
            const authListener = () => {
                this.removeListener(AUTH_EVENT, authListener);
                if (this.authState === AUTH_STATE.AUTHENTICATED) {
                    resolve(this.tokenId);
                }
                if (this.authState === AUTH_STATE.FAILED) {
                    reject(this.authError);
                }
            };
            this.on(AUTH_EVENT, authListener);
        });
    };

    let result;

    switch (this.authState) {
        case AUTH_STATE.AUTHENTICATED:
            result = this._validateToken()
                .then((isValid) => {
                    if (isValid) {
                        return this.tokenId;
                    } else {
                        return waitForAuthentication();
                    }
                });
            break;
        case AUTH_STATE.UNAUTHENTICATED:
            result = waitForAuthentication();
            break;
        case AUTH_STATE.FAILED:
            result = Promise.reject(this.authError);
            break;
    }

    return result;
};

module.exports = SwiftAuthenticator;

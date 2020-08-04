'use strict';

/**
 * OpenStack Swift file adapter for parse-server.
 */

const request = require('request-promise-native');
const SwiftAuthenticator = require('./SwiftAuthenticator');
const logger = require('winston');

function SwiftAdapter(options) {
    this.baseUrl = options.baseUrl + '/AUTH_' + options.projectId + '/' + options.container;
    this.directAccess = options.directAccess || false;

    this.authenticator = new SwiftAuthenticator({
        projectId: options.projectId,
        authUrl: options.authUrl,
        baseUrl: this.baseUrl,
        userId: options.userId,
        password: options.password
    });
}

SwiftAdapter.prototype.createFile = function(filename, data, contentType = null) {
    return this.authenticator.authenticate()
        .then((tokenId) => {
            const options = {
                method: 'PUT',
                uri: this.baseUrl + '/' + filename,
                headers: {
                    'X-Auth-Token': tokenId
                },
                body: data,
                resolveWithFullResponse: true
            };
            if (contentType) {
                options.contentType = contentType;
            }

            return request(options)
                .then((response) => {
                    if (response.statusCode !== 201) {
                        return Promise.reject('Failed with status code ' +  response.statusCode);
                    }
                });
        })
        .catch((err) => {
            logger.error('SwiftAdapter.createFile():', err);
            throw err;
        });

};

SwiftAdapter.prototype.deleteFile = function(filename) {
    return this.authenticator.authenticate()
        .then((tokenId) => {
            const options = {
                method: 'DELETE',
                uri: this.baseUrl + '/' + filename,
                headers: {
                    'X-Auth-Token': tokenId
                },
                resolveWithFullResponse: true
            };

            return request(options)
                .then((response) => {
                    if (response.statusCode !== 204) {
                        return Promise.reject('Failed with status code ' +  response.statusCode);
                    }
                });
        })
        .catch((err) => {
            logger.error('SwiftAdapter.deleteFile():', err);
            throw err;
        });
};

SwiftAdapter.prototype.getFileData = function(filename) {
    return this.authenticator.authenticate()
        .then((tokenId) => {
            const options = {
                method: 'GET',
                uri: this.baseUrl + '/' + filename,
                headers: {
                    'X-Auth-Token': tokenId
                },
                encoding: null,
                resolveWithFullResponse: true
            };

            return request(options)
                .then((response) => {
                    if (response.statusCode !== 200) {
                        return Promise.reject('Failed with status code ' +  response.statusCode);
                    }
                    return response.body;
                });
        })
        .catch((err) => {
            logger.error('SwiftAdapter.getFileData():', err);
            throw err;
        });
};

SwiftAdapter.prototype.getFileLocation = function(config, filename) {
    const encodedFilename = encodeURIComponent(filename);

    if (this.directAccess) {
        return this.baseUrl + '/' + encodedFilename;
    }

    return config.mount + '/files/' + config.applicationId + '/' + encodedFilename;
};

module.exports = SwiftAdapter;

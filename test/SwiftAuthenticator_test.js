'use strict';

const chai = require('chai');
const nock = require('nock');
const SwiftAuthenticator = require('../src/SwiftAuthenticator');

const should = chai.should();
chai.use(require('chai-as-promised'));

// Disable logging for tests.
const winston = require('winston');
winston.remove(winston.transports.Console);

describe('SwiftAuthenticator', function() {

    describe('constructor', () => {
        let options;
        beforeEach(() => {
            options = {
                tenantId: '123',
                authUrl: 'http://api.example.com/v2.0/tokens',
                baseUrl: 'http://api.example.com/v1/AUTH_123/test',
                username: 'username',
                password: 'password'
            };
        });

        it('should initialize', () => {
            const adapter = new SwiftAuthenticator(options);
            adapter.tenantId.should.eql('123');
            adapter.authUrl.should.eql('http://api.example.com/v2.0/tokens');
            adapter.baseUrl.should.eql('http://api.example.com/v1/AUTH_123/test');
            adapter.username.should.eql('username');
            adapter.password.should.eql('password');
            adapter.authState.should.eql(0);
            adapter.isAuthenticating.should.be.false;
            should.not.exist(adapter.tokenId);
            should.not.exist(adapter.authError);
        });
    });

    describe('authenticate', () => {

        let options;

        beforeEach(() => {
            options = {
                tenantId: '123',
                authUrl: 'http://auth.example.com/v2.0/tokens',
                baseUrl: 'http://api.example.com/v1/AUTH_123/test',
                username: 'username',
                password: 'password'
            };
        });

        it('should create new token', () => {
            nock('http://auth.example.com')
                .post('/v2.0/tokens')
                .reply(200, {
                    access: {
                        token: {
                            id: '0123456789'
                        }
                    }
                });

            const authenticator = new SwiftAuthenticator(options);
            authenticator.authenticate().should.eventually.eql('0123456789');
        });

        it('should reuse valid token', () => {
            nock('http://auth.example.com')
                .post('/v2.0/tokens')
                .reply(200, {
                    access: {
                        token: {
                            id: '0123456789'
                        }
                    }
                });

            nock('http://api.example.com')
                .head('/v1/AUTH_123/test')
                .reply(204);

            const authenticator = new SwiftAuthenticator(options);
            authenticator.tokenId = '0123456789';
            authenticator.authenticate().should.eventually.eql('0123456789');
        });

        it('should create new token when invalidated', () => {
            nock('http://auth.example.com')
                .post('/v2.0/tokens')
                .reply(200, {
                    access: {
                        token: {
                            id: '9876543210'
                        }
                    }
                });

            nock('http://api.example.com')
                .head('/v1/AUTH_123/test')
                .reply(401);

            const authenticator = new SwiftAuthenticator(options);
            authenticator.tokenId = '0123456789';
            authenticator.authenticate().should.eventually.eql('9876543210');
        });

        it('should throw when authentication failed', () => {
            nock('http://auth.example.com')
                .post('/v2.0/tokens')
                .reply(401);

            const authenticator = new SwiftAuthenticator(options);
            authenticator.authenticate().should.be.rejected;
        });

    });

});

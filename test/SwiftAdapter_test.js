'use strict';

const chai = require('chai');
const SwiftAdapter = require('../src/SwiftAdapter');
const nock = require('nock');

chai.should();

describe('SwiftAdapter', () => {

    let options;

    beforeEach(() => {
        options = {
            tenantId: '123',
            authUrl: 'http://api.example.com/v2.0/tokens',
            baseUrl: 'http://api.example.com/v1',
            container: 'test',
            username: 'username',
            password: 'password'
        };
    });

    describe('constructor', () => {
        it('should initialize', () => {
            const adapter = new SwiftAdapter(options);
            adapter.baseUrl.should.eql('http://api.example.com/v1/AUTH_123/test');
            adapter.authenticator.should.exist;
            adapter.directAccess.should.be.false;
        });
    });

    const createAdapter = (options) => {
        const adapter = new SwiftAdapter(options);
        adapter.authenticator = {
            authenticate: () => {
                return Promise.resolve('0123456789');
            }
        };
        return adapter;
    };

    describe('createFile', () => {

        it('should create new file', () => {
            nock('http://api.example.com')
                .put('/v1/AUTH_123/test/test.txt', 'test')
                .reply(201);

            const adapter = createAdapter(options);
            adapter.createFile('test.txt', Buffer.from('test'));
        });

        it('should throw when error', () => {
            nock('http://api.example.com')
                .put('/v1/AUTH_123/test/test.txt', 'test')
                .reply(500);

            const adapter = createAdapter(options);
            adapter.createFile('test.txt', Buffer.from('test')).should.be.rejected;
        });

    });

    describe('deleteFile', () => {

        it('should delete file', () => {
            nock('http://api.example.com')
                .delete('/v1/AUTH_123/test/test.txt')
                .reply(204);

            const adapter = createAdapter(options);
            adapter.deleteFile('test.txt');
        });

        it('should throw when error', () => {
            nock('http://api.example.com')
                .delete('/v1/AUTH_123/test/test.txt')
                .reply(500);

            const adapter = createAdapter(options);
            adapter.deleteFile('test.txt').should.be.rejected;
        });

    });

    describe('getFileData', () => {

        it('should delete file', () => {
            nock('http://api.example.com')
                .get('/v1/AUTH_123/test/test.txt')
                .reply(200, 'test');

            const adapter = createAdapter(options);
            adapter.getFileData('test.txt').should.eventually.eql(Buffer.from('test'));
        });

        it('should throw when error', () => {
            nock('http://api.example.com')
                .get('/v1/AUTH_123/test/test.txt')
                .reply(500);

            const adapter = createAdapter(options);
            adapter.getFileData('test.txt').should.be.rejected;
        });

    });

    describe('getFileLocation', () => {

        const config = {
            mount: 'http://www.example.com/parse',
            applicationId: 'abc'
        };

        it('should use parse mount', () => {
            const swiftAdapter = new SwiftAdapter(options);
            swiftAdapter.getFileLocation(config, 'test.png').should.eql('http://www.example.com/parse/files/abc/test.png');
        });

        it('should use baseUrl', () => {
            options.directAccess = true;
            const swiftAdapter = new SwiftAdapter(options);
            swiftAdapter.getFileLocation(config, 'test.png').should.eql('http://api.example.com/v1/AUTH_123/test/test.png');
        });

    });

});

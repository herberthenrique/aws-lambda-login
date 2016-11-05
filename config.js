'use strict';

const configuration = {
	byteSize: 128,
	iterations: 4096,
	tableName: 'users',
	tokenExpiration: '24h',
	secret: 'aws-login-super-secret'
}

module.exports = configuration;
const AWS = require('aws-sdk');
const crypto = require('crypto');
const util = require('util');
const dynamodb = new AWS.DynamoDB();

export function storeUser(email, password, salt, fn) {
  var len = config.byteSize;
  crypto.randomBytes(len, function(err, token) {
    if (err) return fn(err);
    token = token.toString('hex');
    dynamodb.putItem({
      TableName: config.tableName,
      Item: {
        email: {
          S: email
        },
        passwordHash: {
          S: password
        },
        passwordSalt: {
          S: salt
        },
        verifyToken: {
          S: token
        }
      },
      ConditionExpression: 'attribute_not_exists (email)'
    }, function(err, data) {
      if (err) return fn(err);
      else fn(null, token);
    });
  });
}

'use strict';

const AWS = require('aws-sdk');
const crypto = require('crypto');
const util = require('util');
const config = require('./config.js');
const computeHash = require('./security').computeHash;

const dynamodb = new AWS.DynamoDB();
const ses = new AWS.SES();


function storeUser(email, password, name, salt, fn) {
  const len = config.byteSize;
  crypto.randomBytes(len, function(err, token) {
    if (err) return fn(err);
    token = token.toString('hex');
    dynamodb.putItem({
      TableName: config.tableName,
      Item: {
        email: {
          S: email
        },
        name: {
          S: name
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


exports.handler = function(event, context) {
  let email = event.email;
  let clearPassword = event.password;
  let name = event.name;

  computeHash(clearPassword, function(err, salt, hash) {
    if (err) {
      context.fail('Error in hash: ' + err);
    } else {
      storeUser(email, hash, name, salt, function(err, token) {
        if (err) {
          if (err.code == 'ConditionalCheckFailedException') {
            // userId already found
            context.succeed({
              created: false
            });
          } else {
            context.fail('Error in storeUser: ' + err);
          }
        } else {
          context.succeed({
            created: true
          });
        }
      });
    }
  });
}

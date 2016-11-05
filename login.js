'use strict';

const computeHash = require('./security').computeHash;
const jwt = require('jsonwebtoken');
const AWS = require('aws-sdk');
const crypto = require('crypto');
const config = require('./config.js');

// Get reference to AWS clients
const dynamodb = new AWS.DynamoDB();
const cognitoidentity = new AWS.CognitoIdentity();

function getUser(email, fn) {
  dynamodb.getItem({
    TableName: config.tableName,
    Key: {
      email: {
        S: email
      }
    }
  }, function(err, data) {
    if (err) return fn(err);
    else {
      if ('Item' in data) {
        let hash = data.Item.passwordHash.S;
        let salt = data.Item.passwordSalt.S;
        let name = data.Item.name.S;
        fn(null, hash, salt, name);
      } else {
        fn(null, null); // User not found
      }
    }
  });
}

function getToken(email, name) {
  return jwt.sign({ email: email, name: name }, config.secret, {
    expiresIn: config.tokenExpiration
  });
}

exports.handler = function(event, context) {
  let email = event.email;
  let clearPassword = event.password;

  getUser(email, function(err, correctHash, salt, name) {
    if (err) {
      context.fail('Error in getUser: ' + err);
    } else {
      if (correctHash == null) {
        // User not found
        console.log('User not found: ' + email);
        context.succeed({
          login: false
        });
      } else {
        computeHash(clearPassword, salt, function(err, salt, hash) {
          if (err) {
            context.fail('Error in hash: ' + err);
          } else {
            console.log('correctHash: ' + correctHash + ' hash: ' + hash);
            if (hash == correctHash) {
              // Login ok
              console.log('User logged in: ' + email);
              let token = getToken(email, name);
              context.succeed({
                login: true,
                token: token
              });
            } else {
              console.log('User login failed: ' + email);
              context.succeed({
                login: false
              });
            }
          }
        });
      }
    }
  });
}

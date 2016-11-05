'use strict';

const computeHash = require('./security').computeHash;
const jwt = require('jsonwebtoken');
var AWS = require('aws-sdk');
var crypto = require('crypto');
var config = require('./config.js');



// Get reference to AWS clients
var dynamodb = new AWS.DynamoDB();
var cognitoidentity = new AWS.CognitoIdentity();

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
        var hash = data.Item.passwordHash.S;
        var salt = data.Item.passwordSalt.S;
        fn(null, hash, salt);
      } else {
        fn(null, null); // User not found
      }
    }
  });
}

function getToken(email) {
  return jwt.sign({ email: email }, config.secret, {
    expiresIn: config.tokenExpiration
  });
}

exports.handler = function(event, context) {
  var email = event.email;
  var clearPassword = event.password;

  getUser(email, function(err, correctHash, salt) {
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
              let token = getToken(email);
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

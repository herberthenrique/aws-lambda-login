'use strict';

const jwt = require('jsonwebtoken');
const config = require('./config.js');

function verifyToken(token, fn) {
  jwt.verify(token, config.secret, function(err, decoded) {
    if (err) {
      fn({ success: false, message: 'Failed to authenticate token.' }, null);
    } else {
      fn(null, decoded)
    }
  });
}

exports.handler = function(event, context) {
  let token = event.token;
  verifyToken(token, function(err, decoded){
  	if(err) {
		context.fail(err.message);
  	}
  	context.succeed("Hello " + decoded.name);
  })

}

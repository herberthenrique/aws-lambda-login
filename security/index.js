'use strict';

const config = require('../config');
const crypto = require('crypto');

function computeHash(password, salt, fn) {
  // Bytesize
  var len = config.byteSize;
  var iterations = config.iterations;

  if (3 == arguments.length) {
    crypto.pbkdf2(password, salt, iterations, len, fn);
  } else {
    fn = salt;
    crypto.randomBytes(len, function(err, salt) {
      if (err) return fn(err);
      salt = salt.toString('base64');
      crypto.pbkdf2(password, salt, iterations, len, function(err, derivedKey) {
        if (err) return fn(err);
        fn(null, salt, derivedKey.toString('base64'));
      });
    });
  }
}

let securityService = {
  computeHash: computeHash
};

module.exports = securityService;

'use strict';

const crypto = require('crypto');

module.exports = {
  saltKey,
  hashKey,
  verifyKey,
};

/**
 * Adds a `salt` Buffer to the key, if it does not already have one
 *
 * @param {Object} config Configuration for `saluti.password`
 * @param {Object} key A hash of values needed to validate password authentication
 * @param {Function} errback Standard error 1st callback
 **/
function saltKey (config, key, errback) {
key.len = key.len || config.key.len;
  if (typeof key.len !== 'number') {
    errback('len missing');
    return;
  }
  if (key.salt) {
    // If key already has a salt, we should not change it
    errback(undefined, key);
    return;
  }
  crypto.randomBytes(key.len, (err, salt) => {
    key = Object.assign({}, key, { salt });
    errback(undefined, key);
    return;
  });
}

/**
 * Adds a `hash` string to the key
 * Converts `salt` to string if it is not one already
 *
 * @param {Object} config Configuration for `saluti.password`
 * @param {Object} key A hash of values needed to validate password authentication
 * @param {String} pw The password to generate the hash against
 * @param {Function} errback Standard error 1st callback
 **/
function hashKey (config, key, pw, errback) {
  saltKey(config, key, (err, saltedKey) => {

    const alg = key.alg || config.key.alg;
    const len = key.len || config.key.len;
    const iter = key.iter || config.key.iter;
    const digest = config.key.digest;
    const salt = (typeof saltedKey.salt === 'string') ?
      (new Buffer(saltedKey.salt, 'hex')) :
      saltedKey.salt;
    if (!(salt instanceof Buffer)) {
      errback('salt format unsupported');
      return;
    }
    switch (alg) {
    case 'pbkdf2':
      crypto.pbkdf2(pw, salt, iter, len, digest, (err, hash) => {
        /* istanbul ignore if */
        if (err) {
          errback(err);
          return;
        }
        const hashedKey = {
          salt: salt.toString('hex'),
          hash: hash.toString('hex'),
          alg,
          len,
          iter,
        };
        errback(undefined, Object.assign({}, hashedKey));
      });
      break;
    default:
      errback('alg unsupported');
      return;
    }
  });
}

/**
 * Checks to see whether the password when used
 * macthes the claimed key.
 *
 * @param {Object} config Configuration for `saluti.password`
 * @param {Object} claimedKey A hash of values needed to validate password authentication
 * @param {String} pw The password to generate the hash against
 * @param {Function} errback Standard error 1st callback
 **/
function verifyKey (config, claimedKey, pw, errback) {
  if (!claimedKey.salt) {
    errback('salt missing');
    return;
  }
  if (!claimedKey.hash) {
    errback('hash missing');
    return;
  }
  hashKey(config, claimedKey, pw, (err, hashedKey) => {
    /* istanbul ignore if */
    if (err) {
      errback(err);
      return;
    }
    errback(undefined, (claimedKey.hash === hashedKey.hash));
  });
}

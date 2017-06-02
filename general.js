'use strict';

module.exports = {
  generateConfirmCode,
};

/**
 * Generates a confirmation code
 * Code is generated in a non-cryptographically secure manner
 *
 * @param {Object} config Configuration for `saluti.general`
 * @param {Function} errback Standard error 1st callback
 */
function generateConfirmCode (config, errback) {
  const len = config.confirmCode.length;
  let out = '';
  do {
      out = out + Math.random().toString(36).slice(2);
  } while (out.length < len);
  out = out.substr(0, len);
  errback(undefined, out);
}

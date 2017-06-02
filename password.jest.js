'use strict';

const salutiPassword = require('./password.js');


describe('[saluti][password]', () => {

  let saltedKey;
  let hashedKey;

  describe('[saltKey]', () => {

    it('should add salt', (done) => {
      const config = {
        key: {},
      };
      const key = {
        len: 10,
      };
      salutiPassword.saltKey(config, key, (err, result) => {
        expect(err).not.toEqual(expect.anything());
        expect(result).toBeInstanceOf(Object);
        expect(result.salt).toBeInstanceOf(Buffer);
        expect(result.len).toEqual(key.len);
        saltedKey = result;
        done();
      });
    });

    it('should add salt using length from config', (done) => {
      const config = {
        key: {
          len: 10,
        },
      };
      const key = {
      };
      salutiPassword.saltKey(config, key, (err, result) => {
        expect(err).not.toEqual(expect.anything());
        expect(result).toBeInstanceOf(Object);
        expect(result.salt).toBeInstanceOf(Buffer);
        expect(result.len).toEqual(config.key.len);
        done();
      });
    });

    it('should not touch existing salt', (done) => {
      const config = {
        key: {},
      };
      const key = {
        len: 10,
        salt: 'foo',
      };
      salutiPassword.saltKey(config, key, (err, result) => {
        expect(err).not.toEqual(expect.anything());
        expect(result).toBeInstanceOf(Object);
        expect(result.salt).toEqual(key.salt);
        done();
      });
    });

    it('should fail when length is unspecified', (done) => {
      const config = {
        key: {},
      };
      const key = {
      };
      salutiPassword.saltKey(config, key, (err, result) => {
        expect(err).toEqual('len missing');
        done();
      });
    });

  });

  describe('[hashKey]', () => {

    it('should add hash to a salted key', (done) => {
      const config = {
        key: {
          digest: 'sha256',
        },
      };
      const key = Object.assign({
        alg: 'pbkdf2',
        iter: 128,
      }, saltedKey);
      const pw = 'correct password';
      salutiPassword.hashKey(config, key, pw, (err, result) => {
        expect(err).not.toEqual(expect.anything());
        expect(result).toBeInstanceOf(Object);
        expect(typeof result.hash).toEqual('string');
        expect(typeof result.salt).toEqual('string');
        expect(result.alg).toEqual(key.alg);
        expect(result.iter).toEqual(key.iter);
        expect(result.len).toEqual(saltedKey.len);
        hashedKey = result;
        done();
      });
    });

    it('should add hash to a salted key - config', (done) => {
      const config = {
        key: {
          alg: 'pbkdf2',
          iter: 128,
          digest: 'sha256',
        },
      };
      const key = Object.assign({
      }, saltedKey);
      const pw = 'correct password';
      salutiPassword.hashKey(config, key, pw, (err, result) => {
        expect(err).not.toEqual(expect.anything());
        expect(result).toBeInstanceOf(Object);
        expect(typeof result.hash).toEqual('string');
        expect(typeof result.salt).toEqual('string');
        expect(result.alg).toEqual(config.key.alg);
        expect(result.iter).toEqual(config.key.iter);
        expect(result.len).toEqual(saltedKey.len);
        done();
      });
    });

    it('should add salt and hash when salt is missing', (done) => {
      const config = {
        key: {
          alg: 'pbkdf2',
          iter: 128,
          digest: 'sha256',
        },
      };
      const key = Object.assign({
      }, saltedKey);
      key.salt = undefined;
      const pw = 'correct password';
      salutiPassword.hashKey(config, key, pw, (err, result) => {
        expect(err).not.toEqual(expect.anything());
        expect(result).toBeInstanceOf(Object);
        expect(typeof result.hash).toEqual('string');
        expect(typeof result.salt).toEqual('string');
        expect(result.alg).toEqual(config.key.alg);
        expect(result.iter).toEqual(config.key.iter);
        expect(result.len).toEqual(saltedKey.len);
        done();
      });
    });

    it('should not add hash when salt is present but of wrong type', (done) => {
      const config = {
        key: {
          alg: 'pbkdf2',
          iter: 128,
          digest: 'sha256',
        },
      };
      const key = Object.assign({
      }, saltedKey);
      key.salt = 474658459;
      const pw = 'correct password';
      salutiPassword.hashKey(config, key, pw, (err, result) => {
        expect(err).toEqual('salt format unsupported');
        expect(result).not.toEqual(expect.anything());
        done();
      });
    });

    it('should not add hash for unsupported alg', (done) => {
      const config = {
        key: {
          digest: 'sha256',
        },
      };
      const key = Object.assign({
        alg: 'foobaralgo',
        iter: 128,
      }, saltedKey);
      const pw = 'correct password';
      salutiPassword.hashKey(config, key, pw, (err, result) => {
        expect(err).toEqual('alg unsupported');
        expect(result).not.toEqual(expect.anything());
        done();
      });
    });

  });

  describe('[verifyKey]', () => {

    it('should verify true when password matches', (done) => {
      const config = {
        key: {
          digest: 'sha256',
        },
      };
      const key = Object.assign({
      }, hashedKey);
      const pw = 'correct password';
      salutiPassword.verifyKey(config, key, pw, (err, result) => {
        expect(err).not.toEqual(expect.anything());
        expect(result).toEqual(true);
        done();
      });
    });

    it('should verify false when password mismatches', (done) => {
      const config = {
        key: {
          digest: 'sha256',
        },
      };
      const key = Object.assign({
      }, hashedKey);
      const pw = 'wrong password';
      salutiPassword.verifyKey(config, key, pw, (err, result) => {
        expect(err).not.toEqual(expect.anything());
        expect(result).toEqual(false);
        done();
      });
    });

    it('should verify false when digest is different', (done) => {
      const config = {
        key: {
          digest: 'sha512',
        },
      };
      const key = Object.assign({
      }, hashedKey);
      const pw = 'correct password';
      salutiPassword.verifyKey(config, key, pw, (err, result) => {
        expect(err).not.toEqual(expect.anything());
        expect(result).toEqual(false);
        done();
      });
    });

    it('should not verify when salt missing', (done) => {
      const config = {
        key: {
          digest: 'sha256',
        },
      };
      const key = Object.assign({
      }, hashedKey);
      key.salt = undefined;
      const pw = 'correct password';
      salutiPassword.verifyKey(config, key, pw, (err, result) => {
        expect(err).toEqual('salt missing');
        expect(result).not.toEqual(expect.anything());
        done();
      });
    });

    it('should not verify when salt missing', (done) => {
      const config = {
        key: {
          digest: 'sha256',
        },
      };
      const key = Object.assign({
      }, hashedKey);
      key.hash = undefined;
      const pw = 'correct password';
      salutiPassword.verifyKey(config, key, pw, (err, result) => {
        expect(err).toEqual('hash missing');
        expect(result).not.toEqual(expect.anything());
        done();
      });
    });

  });

});

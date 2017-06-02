'use strict';

const salutiGeneral = require('./general.js');

describe('[saluti][general]', () => {

  describe('[generateConfirmCode]', () => {

    it('should generate', () => {
      const config = {
        confirmCode: {
          length: 32,
        },
      };
      salutiGeneral.generateConfirmCode(config, (err, result) => {
        expect(err).not.toEqual(expect.anything());
        expect(typeof result).toEqual('string');
        expect(result.length).toEqual(config.confirmCode.length);
      });
    });

  });


});

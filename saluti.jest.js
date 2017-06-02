'use strict';

describe('[saluti]', () => {

  it('should link to submodules', () => {
    const saluti = require('./saluti.js');
    const moduleNames = Object.keys(saluti).sort();
    expect(moduleNames).toMatchSnapshot();
  });

});

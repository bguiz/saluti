'use strict';

const eslintrc = {
  env: {
    es6: true,
    jest: true,
  },
  rules: {
    'comma-dangle': ['error', 'always-multiline'],
    'no-undef-init': ['error'],
    'no-undefined': ['off'],
    'quote-props': ['off'],
  },
  parserOptions: {
    'sourceType': 'script',
  },
};

module.exports = eslintrc;

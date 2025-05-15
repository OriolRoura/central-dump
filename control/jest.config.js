module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/src/**/*.test.ts'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  globals: {
    'ts-jest': {
      tsconfig: 'tsconfig.json',
    },
  },
};
module.exports = {
  roots: ['<rootDir>'],
  testMatch: ['**/src/**/*.test.ts'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  testEnvironment: 'node',
};

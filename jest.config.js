module.exports = {
  testEnvironment: 'node',
  coverageDirectory: 'coverage',
  collectCoverageFrom: [
    'src/**/*.js',
    '!src/examples/**',
    '!**/node_modules/**'
  ],
  testMatch: [
    '**/test/**/*.test.js'
  ],
  setupFiles: ['<rootDir>/test/setup.js'],
  verbose: true,
  clearMocks: true,
  restoreMocks: true
}; 
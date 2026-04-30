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
  restoreMocks: true,
  // Force Jest to exit after all tests complete so background async handles
  // from the mongoose connection attempt in Redis-mode tests don't stall CI.
  forceExit: true
}; 
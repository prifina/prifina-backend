
module.exports = {
  // Stop running tests after `n` failures
  bail: true,
  verbose: true,
  testPathIgnorePatterns: ["/node_modules/"],
  // The glob patterns Jest uses to detect test files
  testMatch: [
    "**/*.test.js",
    //"**/__tests__/*.test.js",
    //"**/__tests__/**/*.[jt]s?(x)",
    //   "**/?(*.)+(spec|test).[tj]s?(x)"
  ],
}   
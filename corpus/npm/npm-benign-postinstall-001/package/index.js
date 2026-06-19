// Benign decoy fixture. A small, ordinary logger implementation.
const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

function createLogger(min = "info") {
  const threshold = LEVELS[min] || LEVELS.info;
  return Object.fromEntries(
    Object.keys(LEVELS).map((level) => [
      level,
      (...args) => {
        if (LEVELS[level] >= threshold) console.log(`[${level}]`, ...args);
      },
    ])
  );
}

module.exports = { createLogger };

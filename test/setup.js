process.env.NODE_ENV = 'test';

// Mute logs during tests
console.log = jest.fn();
console.error = jest.fn();
console.warn = jest.fn(); 
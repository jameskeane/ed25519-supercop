const bindings = require('node-gyp-build')(__dirname)


/**
 * Signs a message with a secret key and returns the signature.
 * @param {string|Buffer} message The message to sign.
 * @param {string|Buffer} publicKey The public key to verify the signature, either a hex encoded string or raw buffer.
 * @param {string|Buffer} secretKey The secret key to sign the message, either a hex encoded string or raw buffer.
 * @returns {Buffer} A 64 byte buffer containing the signature.
 */
function sign(message, publicKey, secretKey) {
  if (typeof message === 'string') message = Buffer.from(message);
  if (!Buffer.isBuffer(message)) throw new Error('message must be a buffer or a string');

  if (typeof publicKey === 'string') publicKey = Buffer.from(publicKey, 'hex');
  if (!Buffer.isBuffer(publicKey)) throw new Error('public key must be a buffer or hex string');

  if (typeof secretKey === 'string') secretKey = Buffer.from(secretKey, 'hex');
  if (!Buffer.isBuffer(secretKey)) throw new Error('secret key must be a buffer or hex string');

  const sig = Buffer.alloc(64);
  bindings.node_supercop_sign(message, publicKey, secretKey, sig);
  return sig;
}


/**
 * Verifies a signature with a public key.
 * @param {string|Buffer} signature The signature to verify.
 * @param {string|Buffer} message The message to verify.
 * @param {string|Buffer} publicKey The public key to verify the signature.
 * @returns {boolean} A boolean indicating whether the signature is valid.
 */
function verify(signature, message, publicKey) {
  if (typeof signature === 'string') signature = Buffer.from(signature, 'hex');
  if (!Buffer.isBuffer(signature)) throw new Error('message must be a buffer or a string');

  if (typeof message === 'string') message = Buffer.from(message);
  if (!Buffer.isBuffer(message)) throw new Error('message must be a buffer or a string');

  if (typeof publicKey === 'string') publicKey = Buffer.from(publicKey, 'hex');
  if (!Buffer.isBuffer(publicKey)) throw new Error('public key must be a buffer or hex string');

  return bindings.node_supercop_verify(signature, message, publicKey) === 1;
}


/**
 * Generate a 32-byte buffer of cryptographically secure random data.
 * @returns {Buffer} A 32 byte buffer containing a random seed.
 */
function createSeed() {
  const seed = Buffer.alloc(32);
  bindings.node_supercop_create_seed(seed);
  return seed;
}


/**
 * Creates a new key pair from a seed value.
 * @param {string|Buffer} seed The seed value to generate the key pair from.
 * @returns {{publicKey: Buffer, secretKey: Buffer}} An object containing the public and secret keys.
 */
function createKeyPair(seed) {
  if (typeof seed === 'string') seed = Buffer.from(seed, 'hex');
  if (!Buffer.isBuffer(seed)) throw new Error('seed must be a buffer or hex string');

  const res = { publicKey: Buffer.alloc(32), secretKey: Buffer.alloc(64) };
  bindings.node_supercop_create_key_pair(seed, res.publicKey, res.secretKey);
  return res;
}


/**
 * Generate a shared secret using Diffie–Hellman on the montgomery curve.
 * @param {string|Buffer} publicKey The public key to verify the signature.
 * @param {string|Buffer} secretKey The secret key to sign the message.
 * @returns {Buffer} A 32 byte buffer containing the shared secret.
 */
function exchangeKeys(publicKey, secretKey) {
  if (typeof publicKey === 'string') publicKey = Buffer.from(publicKey, 'hex');
  if (!Buffer.isBuffer(publicKey)) throw new Error('public key must be a buffer or hex string');

  if (typeof secretKey === 'string') secretKey = Buffer.from(secretKey, 'hex');
  if (!Buffer.isBuffer(secretKey)) throw new Error('secret key must be a buffer or hex string');

  const sharedSecret = Buffer.alloc(32);
  bindings.node_supercop_exchange_keys(publicKey, secretKey, sharedSecret);
  return sharedSecret;
}

module.exports = { sign, verify, createSeed, createKeyPair, exchangeKeys };

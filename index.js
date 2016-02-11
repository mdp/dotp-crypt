var nacl = require('./lib/tweetnacl-fast')
var blake2 = require('blakejs')
var Base58 = require('bs58')

var VERSION = 0

exports.utils = {
  Base58: Base58,
  nacl: nacl,
  blake2: blake2
}

function toArrayBuffer(buffer) {
    var ab = new ArrayBuffer(buffer.length);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buffer.length; ++i) {
        view[i] = buffer[i];
    }
    return view;
}

function crypto_box_seal_open(enc, publicKey, secretKey){
  var ephemeralPk = enc.subarray(0,32)
  var box = enc.subarray(32)
  var ctx = blake2.blake2b_init(24)
  blake2.blake2b_update(ctx, ephemeralPk)
  blake2.blake2b_update(ctx, publicKey)
  var nonce = blake2.blake2b_final(ctx)
  var result = nacl.box.open(box, nonce, ephemeralPk, secretKey)
  return result
}

function crypto_box_seal(otp, recipienPublicKey, ephemeralSecretKey){
  var ephemeralKp = nacl.box.keyPair.fromSecretKey(ephemeralSecretKey)
  var ctx = blake2.blake2b_init(24)
  blake2.blake2b_update(ctx, ephemeralKp.publicKey)
  blake2.blake2b_update(ctx, recipienPublicKey)
  var nonce = blake2.blake2b_final(ctx)
  var box = nacl.box(otp, nonce, recipienPublicKey, ephemeralKp.secretKey)
  var sealedBox = new Uint8Array(32+box.length)
  sealedBox.set(ephemeralKp.publicKey, 0)
  sealedBox.set(box, 32)
  return sealedBox
}

exports.crypto_box_seal = crypto_box_seal
exports.crypto_box_seal_open = crypto_box_seal_open

exports.getKeyPair = function(secretKey) {
  return nacl.box.keyPair.fromSecretKey(secretKey)
}

exports.getPublicID = function(publicKey){
  var address = new Uint8Array(33)
  var digest = nacl.hash(publicKey)
  var checkdigit = digest[0]
  address.set(publicKey,0)
  address[32] = checkdigit
  return Base58.encode(address)
}

exports.getRandomKeyPair = function(randomArray) {
  var privateKey = new Uint8Array(randomArray)
  return exports.getKeyPair(privateKey)
}

exports.deriveKeyPair = function(input) {
  var secretKey
  if (typeof input === 'string') {
    var digest = nacl.hash(new Buffer(input))
    secretKey = toArrayBuffer(digest).subarray(0,32)
  } else {
    var digest = nacl.hash(input)
    secretKey = toArrayBuffer(digest).subarray(0,32)
  }
  return exports.getKeyPair(secretKey)
}

exports.getPublicKeyFromPublicID = function(publicID) {
  var addr = new Uint8Array(Base58.decode(publicID))
  if (addr.length !== 33) {
    throw(new Error('Bad Public ID, incorrect length'))
  }
  var pubKey = addr.subarray(0,32)
  var checkdigit = nacl.hash(pubKey)[0]
  if (checkdigit !== addr[32]) {
    throw(new Error('Bad Public ID, failed check digit'))
  }
  return pubKey
}

exports.decryptChallenge = function(challenge, keyPair) {
  var c = exports.deserializeChallenge(challenge)
  return crypto_box_seal_open(c.box, keyPair.publicKey, keyPair.secretKey)
}

exports.buildChallenge = function(recPubKeyFirstByte, box) {
  var challenge = new Uint8Array(1+1+box.length)
  challenge[0] = VERSION
  challenge[1] = recPubKeyFirstByte
  challenge.set(box, 2)
  return challenge
}

exports.serializeChallenge = function(recPubKeyFirstByte, box) {
  var chalBytes = exports.buildChallenge(recPubKeyFirstByte, box)
  return Base58.encode(chalBytes)
}

exports.deserializeChallenge = function(challengeB58) {
  var challenge = new Uint8Array(Base58.decode(challengeB58))
  if (challenge[0] > VERSION) {
    throw(new Error('Unsupported version:', challenge[0]))
  }
  return {
    version: challenge[0],
    publicKeyFirstByte: challenge[1],
    box: challenge.subarray(2),
  }
}

exports.createChallenge = function(otp, recipientAddrB58, randomSeed) {
  var publicKey = exports.getPublicKeyFromPublicID(recipientAddrB58)
  var ephemeralKp = nacl.box.keyPair.fromSecretKey(randomSeed)
  var box = crypto_box_seal(otp, publicKey, ephemeralKp.secretKey)
  return exports.serializeChallenge(publicKey[0], box)
}


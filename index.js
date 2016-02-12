var nacl = require('./lib/tweetnacl-fast')
var blake2 = require('blakejs')
var Base58 = require('bs58')
var Base32 = require('base32.js')
var Buffer = require('buffer').Buffer

var VERSION = 0

//TODO: @mdp Documents all the public methods

exports.utils = {
  Base58: Base58,
  Base32: Base32,
  nacl: nacl,
  blake2: blake2
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

function QR32Decode(str) {
  str = str.replace(/\-/g,'=')
  var decoder = new Base32.Decoder();
  return decoder.write(str).finalize();
}

function QR32Encode(bytes) {
  var encoder = new Base32.Encoder();
  return encoder.write(bytes).finalize().replace(/\=/g, '-')
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
    var digest = nacl.hash(nacl.util.decodeUTF8(input))
    secretKey = digest.subarray(0,32)
  } else {
    var digest = nacl.hash(input)
    secretKey = digest.subarray(0,32)
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

exports.buildChallenge = function(recPubKeyFirstByte, box) {
  var challenge = new Uint8Array(1+1+box.length)
  challenge[0] = VERSION
  challenge[1] = recPubKeyFirstByte
  challenge.set(box, 2)
  return challenge
}

exports.serializeChallenge = function(recPubKeyFirstByte, box) {
  var chalBytes = exports.buildChallenge(recPubKeyFirstByte, box)
  return QR32Encode(chalBytes)
}

exports.deserializeChallenge = function(challengeQR32) {
  var challenge = new Uint8Array(QR32Decode(challengeQR32))
  if (challenge[0] > VERSION) {
    throw(new Error('Unsupported version:', challenge[0]))
  }
  return {
    version: challenge[0],
    publicKeyFirstByte: challenge[1],
    box: challenge.subarray(2),
  }
}

exports.decryptChallenge = function(challenge, keyPair) {
  var c = exports.deserializeChallenge(challenge)
  var decoded = crypto_box_seal_open(c.box, keyPair.publicKey, keyPair.secretKey)
  if (decoded) {
    var decodedStr = new Buffer(decoded).toString()
    var id = decodedStr.substring(0, decodedStr.indexOf('|'))
    var otp = decodedStr.substring(id.length+1)
    return {
      id: id,
      otp: otp
    }
  }
  return false
}

// Create a challenge for the recipient
exports.createChallenge = function(otp, recipientAddrB58, challengerId, ephemeralSecret) {
  var publicKey = exports.getPublicKeyFromPublicID(recipientAddrB58)
  var content = challengerId + '|' + otp
  var box = crypto_box_seal(new Buffer(content), publicKey, ephemeralSecret)
  return exports.serializeChallenge(publicKey[0], box)
}


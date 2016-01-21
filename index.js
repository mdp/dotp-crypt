var nacl = require('./lib/tweetnacl-fast.js')
var Buffer = require('buffer').Buffer
var Base58 = require('bs58')

var VERSION = 0

exports.utils = {
  Base58: Base58,
  nacl: nacl,
}

exports.nacl = nacl

function zeroNonce() {
  var nonce = new Uint8Array(24)
  for (var i = 0; i < 24; i++) { nonce[i] = 0 }
  return nonce
}

function toArrayBuffer(buffer) {
    var ab = new ArrayBuffer(buffer.length);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buffer.length; ++i) {
        view[i] = buffer[i];
    }
    return view;
}

exports.getKeyPair = function(privateKey) {
  return nacl.box.keyPair.fromSecretKey(privateKey)
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
  var digest = nacl.hash(new Buffer(input))
  var privateKey = toArrayBuffer(digest.subarray(0,32))
  return exports.getKeyPair(privateKey)
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

exports.decryptChallenge = function(challenge, secretKey) {
  var c = exports.deserializeChallenge(challenge)
  var nonce = zeroNonce()
  return nacl.box.open(c.box, nonce, c.challengerPublicKey, secretKey)
}

exports.buildChallenge = function(recPubKeyFirstByte, challengerPub, box) {
  var challenge = new Uint8Array(1+1+32+box.length)
  challenge[0] = VERSION
  challenge[1] = recPubKeyFirstByte
  challenge.set(challengerPub, 2)
  challenge.set(box, 34)
  return challenge
}

exports.serializeChallenge = function(recPubKeyFirstByte, challengerPub, box) {
  var chalBytes = exports.buildChallenge(recPubKeyFirstByte, challengerPub, box)
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
    challengerPublicKey: challenge.subarray(2,34),
    box: challenge.subarray(34),
  }
}

exports.createChallenge = function(otp, challengerKeyPair, recipientAddrB58) {
  var publicKey = exports.getPublicKeyFromPublicID(recipientAddrB58)
  var nonce = zeroNonce()
  var box = nacl.box(otp, nonce, publicKey, challengerKeyPair.secretKey)
  return exports.serializeChallenge(publicKey[0], challengerKeyPair.publicKey, box)
}


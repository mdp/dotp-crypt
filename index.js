var nacl = require('tweetnacl')
var Base58 = require('bs58')
var Promise = require('bluebird')

const VERSION = 0

exports.utils = {
  Base58: Base58,
  nacl: nacl,
}

exports.nacl = nacl

function intTo5Bytes(i) {
  // 40 bits signed for the timestamp since JS 53 bit precision
  // Fails on Jan-25-19391
  var arr = new Uint8Array(5)
  arr[0] = i >> 32
  arr[1] = (i >> 24) & 255
  arr[2] = (i >> 16) & 255
  arr[3] = (i >> 8) & 255
  arr[4] = i & 255
  return arr
}

function fiveBytesToInt(byteArr) {
  var i = (byteArr[0] << 32) |
    (byteArr[1] << 24) |
    (byteArr[2] << 16) |
    (byteArr[3] << 8) |
    byteArr[4]
  return i
}

exports.getKeyPair = function(privateKey) {
  return nacl.box.keyPair.fromSecretKey(privateKey)
}

exports.getPublicID = function(publicKey){
  var address = new Uint8Array(33)
  var checkdigit = nacl.hash(publicKey)[0]
  address.set(publicKey,0)
  address[32] = checkdigit
  return Base58.encode(address)
}

exports.getPublicKeyFromPublicID = function(publicID) {
  var addr = Base58.decode(publicID)
  if (addr.length !== 33) {
    throw(new Error('Bad Public ID, incorrect length'))
  }
  var pubKey = new Uint8Array(addr.subarray(0,32))
  var checkdigit = nacl.hash(pubKey)[0]
  if (checkdigit !== addr[32]) {
    throw(new Error('Bad Public ID, failed check digit'))
  }
  return pubKey
}

exports.decryptChallenge = function(challenge, secretKey) {
  var c = exports.deserializeChallenge(challenge)
  return nacl.box.open(c.box, c.nonce, c.challengerPublicKey, secretKey)
}

exports.serializeChallenge = function(expiresAt, recPubKeyFirstByte, nonce, challengerPub, box) {
  var challenge = new Uint8Array(1+5+1+24+32+box.length)
  var expiresAtArr = intTo5Bytes(expiresAt)
  challenge[0] = VERSION
  challenge.set(expiresAtArr, 1)
  challenge[6] = recPubKeyFirstByte
  challenge.set(nonce, 7)
  challenge.set(challengerPub, 31)
  challenge.set(box, 63)
  return Base58.encode(challenge)
}

exports.deserializeChallenge = function(challengeB58) {
  var challenge = new Uint8Array(Base58.decode(challengeB58))
  if (challenge[0] > VERSION) {
    throw(new Error('Unsupported version:', challenge[0]))
  }
  return {
    version: challenge[0],
    expiresAt: fiveBytesToInt(challenge.subarray(1,6)),
    publicKeyFirstByte: challenge[6],
    nonce: challenge.subarray(7,31),
    challengerPublicKey: challenge.subarray(31,63),
    box: challenge.subarray(63),
  }
}

exports.createChallenge = function(otp, nonce, expiresAt, challengerKeyPair, recipientAddrB58) {
  var publicKey = exports.getPublicKeyFromPublicID(recipientAddrB58)
  var box = nacl.box(otp, nonce, publicKey, challengerKeyPair.secretKey)
  return exports.serializeChallenge(expiresAt, publicKey[0], nonce, challengerKeyPair.publicKey, box)
}

exports.createChallengeResponseToken = function(data, nonce, secretKey) {
  var msg = new Uint8Array(new Buffer(JSON.stringify(data)))
  var secretBox = nacl.secretbox(msg, nonce, secretKey)
  var token = new Uint8Array(24+secretBox.length)
  token.set(nonce, 0)
  token.set(secretBox, 24)
  return Base58.encode(token)
}

exports.decodeChallengeResponseToken = function(responseToken, secretKey) {
  var token = new Uint8Array(Base58.decode(responseToken))
  var nonce = token.subarray(0,24)
  var box = token.subarray(24)
  var decrypted = nacl.secretbox.open(box, nonce, secretKey)
  return  {
    data: JSON.parse(new Buffer(decrypted).toString()),
    nonce: nonce,
  }
}

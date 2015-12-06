var BLAKE2s = require('blake2s-js')
var scrypt = require('scrypt-async')
var nacl = require('tweetnacl')
var Base58 = require('bs58')
var Promise = require('bluebird')


exports.utils = {
  Base58: Base58,
}

exports.nacl = nacl

function intTo5Bytes(i) {
  var arr = new Uint8Array(5) // 40 bits for the timestamp
  arr[0] = 0 // Fails on 2038, hopefully JS handles >32 bit by then
  arr[1] = i >> 24
  arr[2] = (i >> 16) & 255
  arr[3] = (i >> 8) & 255
  arr[4] = i & 255
  return arr
}

function fiveBytesToInt(byteArr) {
  var i = (byteArr[1] << 24) |
    (byteArr[2] << 16) |
    (byteArr[3] << 8) |
    byteArr[4]
  return i
}
exports.getKeyPair = function(key, salt) {
  return new Promise(function(fulfill, reject){
    var h = new BLAKE2s(32)
    h.update(new Buffer(key,'utf-8'))
    var keyHash = h.digest()
    scrypt(keyHash, new Buffer(salt,'utf-8'), 17, 8, 32, function(result){
      var kp = nacl.box.keyPair.fromSecretKey(new Uint8Array(result))
      fulfill(kp)
    })
  })
}

exports.getMiniLockID = function(publicKey){
  var address = new Uint8Array(33)
  var h = new BLAKE2s(1)
  h.update(publicKey)
  var checkdigit = h.digest()
  address.set(publicKey)
  address[32] = checkdigit
  return Base58.encode(address)
}

exports.getPublicKeyFromMiniLockID = function(miniLockId) {
  var addr = Base58.decode(miniLockId)
  if (addr.length !== 33) {
    throw(new Error('Bad MiniLock ID, incorrect length'))
  }
  var pubKey = new Uint8Array(addr.slice(0,32))
  var h = new BLAKE2s(1)
  h.update(pubKey)
  var checkdigit = h.digest()[0]
  if (checkdigit !== addr[32]) {
    throw(new Error('Bad MiniLock ID, failed check digit'))
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
  challenge[0] = 1 // Version
  challenge.set(expiresAtArr, 1)
  challenge[6] = recPubKeyFirstByte
  challenge.set(nonce, 7)
  challenge.set(challengerPub, 31)
  challenge.set(box, 63)
  return Base58.encode(challenge)
}

exports.deserializeChallenge = function(challengeB58) {
  var challenge = new Uint8Array(Base58.decode(challengeB58))
  return {
    version: challenge[0],
    expiresAt: fiveBytesToInt(challenge.slice(1,6)),
    publicKeyFirstByte: challenge[6],
    nonce: challenge.slice(7,31),
    challengerPublicKey: challenge.slice(31,63),
    box: challenge.slice(63),
  }
}

exports.createChallenge = function(otp, nonce, expiresAt, challengerKeyPair, recipientAddrB58) {
  var publicKey = exports.getPublicKeyFromMiniLockID(recipientAddrB58)
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
  var nonce = token.slice(0,24)
  var box = token.slice(24)
  var decrypted = nacl.secretbox.open(box, nonce, secretKey)
  return  {
    data: JSON.parse(new Buffer(decrypted).toString()),
    nonce: nonce,
  }
}

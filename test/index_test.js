var dotpCrypt = require('../index.js')
var assert = require('assert')
var Promise = require('bluebird')

// Static variables for testing
var NONCE = new Uint8Array([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23])
var EXPIRE_AT = 1452759001

describe('The challenge byte array', function() {
  var challengerKeyPair = dotpCrypt.deriveKeyPair('ServerSecret')
  var box = [0,1,2,3,4,5,6]
  it('should build an challenge byte array', function () {
    var expectedChallenge = new Uint8Array([0, 0, 86, 151, 87, 217, 23, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 93, 2, 57, 238, 218, 252, 48, 190, 44, 91, 2, 192, 74, 235, 41, 39, 146, 243, 103, 143, 195, 25, 14, 57, 254, 29, 156, 118, 1, 132, 85, 78, 0, 1, 2, 3, 4, 5, 6])
    var challengeBytes = dotpCrypt.buildChallenge(EXPIRE_AT, 23, NONCE, challengerKeyPair.publicKey, box)
    assert.deepEqual(challengeBytes, expectedChallenge)
  })
  it('should serialize and deserialize an array', function () {
    var challenge = dotpCrypt.serializeChallenge(EXPIRE_AT, 23, NONCE, challengerKeyPair.publicKey, box)
    var d = dotpCrypt.deserializeChallenge(challenge)
    assert.equal(EXPIRE_AT, d.expiresAt)
    assert.deepEqual(box, d.box)
    assert.deepEqual(challengerKeyPair.publicKey, d.challengerPublicKey)
  })
})

describe('Deriving a keypair from a string', function() {
  it('use sha512/256 to derive a keypair', function () {
    var keyPair = dotpCrypt.deriveKeyPair('TEST')
    var expectedPublicKey = new Uint8Array([178, 52, 221, 72, 147, 67, 27, 234, 88, 14, 14, 203, 48, 76, 47, 15, 133, 234, 195, 29, 127, 154, 198, 193, 116, 245, 201, 225, 223, 167, 217, 119])
    assert.deepEqual(keyPair.publicKey, expectedPublicKey)
  })
  it('correctly format the publicId', function () {
    var keyPair = dotpCrypt.deriveKeyPair('TEST')
    var pubID = dotpCrypt.getPublicID(keyPair.publicKey)
    var expectedPublicID = 'uwRjspFVUtLh9AFNBGS7ehDoy7gNadefHPQ5WTowSygW6'
    assert.deepEqual(pubID, expectedPublicID)
  })
})

describe('Challenge generation and decrypting', function() {
  var challengerKeyPair = dotpCrypt.deriveKeyPair('ServerSecret')
  var recKeyPair = dotpCrypt.deriveKeyPair('ClientSecret')
  it('should create a challenge for the recipient', function () {
    var recipientID = dotpCrypt.getPublicID(recKeyPair.publicKey)
    var challenge = dotpCrypt.createChallenge(new Buffer('MYOTP','utf-8'), NONCE, EXPIRE_AT, challengerKeyPair, recipientID)
    assert.equal('11KPBbA6tVpE9mLxEiGyQfKKtnnMdZPQrHevRRXKqtZ6AKZ9tFfi9CruaRSiCuqMB8g4zNc5mkkMxHRzYEwZUZfKUErUu2kca8e4pLABaZBUGVw922', challenge)
    assert.equal(new Buffer(dotpCrypt.decryptChallenge(challenge, recKeyPair.secretKey)).toString(), 'MYOTP')
  });
});

describe('Response token and decoding', function() {
  var secretKey = new Uint8Array(32).fill(1)
  it('should create a token and decode it', function () {
    var data = {
      otp: 'myotp',
      expiresAt: EXPIRE_AT,
    }
    var token = dotpCrypt.createChallengeResponseToken(data, NONCE, secretKey)
    var decodedToken = dotpCrypt.decodeChallengeResponseToken(token, secretKey)
    assert.equal(decodedToken.data.expiresAt, EXPIRE_AT)
    assert.equal(decodedToken.data.otp, 'myotp')
  });
});

var dotpCrypt = require('../index.js')
var assert = require('assert')
var sodium = require('libsodium-wrappers');

function toHex(arr) {
  var h = '0123456789abcdef', s = '';
  for (var i = 0; i< arr.length; i++) {
    s += h[(arr[i]>>4)&15];
    s += h[arr[i]&15];
  }
  return s;
}

describe('The challenge byte array', function() {
  var challengerKeyPair = dotpCrypt.deriveKeyPair('ServerSecret')
  var box = [0,1,2,3,4,5,6]
  it('should build an challenge byte array', function () {
    var expectedChallenge = new Uint8Array([0, 23, 0, 1, 2, 3, 4, 5, 6])
    var challengeBytes = dotpCrypt.buildChallenge(23, box)
    assert.deepEqual(challengeBytes, expectedChallenge)
  })
  it('should serialize and deserialize an array', function () {
    var challenge = dotpCrypt.serializeChallenge(23, box)
    var d = dotpCrypt.deserializeChallenge(challenge)
    assert.equal(23, d.publicKeyFirstByte)
    assert.deepEqual(box, d.box)
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

describe('Challenge generation and encryption', function() {
  var recKeyPair = dotpCrypt.deriveKeyPair('ClientSecret')
  var randomSeed = new Uint8Array(32).fill(1)
  it('should create a challenge for the recipient', function () {
    var recipientID = dotpCrypt.getPublicID(recKeyPair.publicKey)
    var challenge = dotpCrypt.createChallenge('MYOTP', recipientID, 'github.com', randomSeed)
    var decoded = dotpCrypt.decryptChallenge(challenge, recKeyPair)
    assert.equal(decoded.otp, 'MYOTP')
    assert.equal(decoded.id, 'github.com')
  });
});

// LibSodium.js is a bit difficult to use with React Native at this point
// TweetNacl only needs a bit of work, so we instead just use it for now.
describe('Interop with LibSodium', function() {
  var kp = sodium.crypto_box_keypair()
  var ephemeralKp = sodium.crypto_box_keypair()
  it('should be compatible with decryption', function () {
    var enc = dotpCrypt.crypto_box_seal(new Buffer('foo', 'utf-8'), kp.publicKey, ephemeralKp.privateKey)
    var result = sodium.crypto_box_seal_open(enc, kp.publicKey, kp.privateKey)
    assert.equal(new Buffer(result).toString(), 'foo')
  });
  it('should be compatible with encryption', function () {
    var enc = sodium.crypto_box_seal(new Buffer('foo12'), kp.publicKey)
    var result = dotpCrypt.crypto_box_seal_open(enc, kp.publicKey, kp.privateKey)
    assert.equal(new Buffer(result).toString(), 'foo12')
  });
});



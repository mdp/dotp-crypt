var dotpCrypt = require('../index.js')
var assert = require('assert')
var Promise = require('bluebird')

describe('KeyPair generation', function() {
  var passphrase = 'This passphrase is supposed to be good enough for miniLock. :-)'
  var salt = 'miniLockScrypt..'
  it('should match the MiniLock impl', function (done) {
    dotpCrypt.getKeyPair(passphrase, salt)
    .then(function(kp){
      assert.equal(dotpCrypt.utils.Base58.encode(kp.publicKey), 'EWVHJniXUFNBC9RmXe45c8bqgiAEDoL3Qojy2hKt4c4e')
      assert.equal(dotpCrypt.getMiniLockID(kp.publicKey), '22d9pyWnHVGQTzCCKYEYbL4YmtGfjMVV3e5JeJUzLNum8A')
      done()
    })
  });
});

describe('The challenge byte array', function() {
  var nonce = [189, 70, 242, 241, 234, 4, 215, 66, 27, 160, 95, 160, 95, 61, 44, 45, 132, 254, 215, 227, 34, 155, 243, 1]
  var senderPublicKey = [245, 245, 220, 62, 205, 52, 252, 99, 237, 244, 114, 248, 154, 44, 77, 2, 156, 228, 111, 147, 149, 187, 54, 237, 113, 30, 152, 58, 253, 116, 83, 196]
  var expiresAt = 1449358943
  var box = [0,1,2,3,4,5,6]
  it('should serialize and deserialize an array', function () {
    var challenge = dotpCrypt.serializeChallenge(expiresAt, 25, nonce, senderPublicKey, box)
    var d = dotpCrypt.deserializeChallenge(challenge)
    assert.equal(expiresAt, d.expiresAt)
    assert.deepEqual(box, d.box)
    assert.deepEqual(senderPublicKey, d.challengerPublicKey)
  })
})

describe('Challenge generation and decrypting', function() {
  var challengerKeyPair = dotpCrypt.nacl.box.keyPair.fromSecretKey(new Uint8Array(32).fill(1))
  var recKeyPair = dotpCrypt.nacl.box.keyPair.fromSecretKey(new Uint8Array(32).fill(2))
  it('should create a challenge for the recipient', function () {
    var recipientID = dotpCrypt.getMiniLockID(recKeyPair.publicKey)
    var expiresAt = Math.floor(Date.now()/1000) + 120
    var challenge = dotpCrypt.createChallenge(new Buffer('myotp','utf-8'), new Buffer(24), expiresAt, challengerKeyPair, recipientID)
    assert.equal(new Buffer(dotpCrypt.decryptChallenge(challenge, recKeyPair.secretKey)).toString(), 'myotp')
  });
});

describe('Response token and decoding', function() {
  var secretKey = new Uint8Array(32).fill(1)
  var nonce = new Uint8Array(24).fill(3)
  var expiresAt = Math.floor(Date.now()/1000)
  it('should create a token and decode it', function () {
    var data = {
      otp: 'myotp',
      expiresAt: expiresAt,
    }
    var token = dotpCrypt.createChallengeResponseToken(data, nonce, secretKey)
    console.log(token)
    var decodedToken = dotpCrypt.decodeChallengeResponseToken(token, secretKey)
    console.log(decodedToken)
    assert.equal(decodedToken.data.expiresAt, expiresAt)
    assert.equal(decodedToken.data.otp, 'myotp')
  });
});

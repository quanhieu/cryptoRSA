const { writeFileSync } = require('fs')
const crypto = require('crypto')
const nodeRSA = require('node-rsa')
const path = require('path')
const fs = require('fs')

function generateKeys() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: 'pkcs1',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: '',
    },
  })

  writeFileSync('private_rsa.pem', privateKey)
  writeFileSync('public_ras.pem', publicKey)
}

function encrypt(toEncrypt, relativeOrAbsolutePathToPublicKey) {
  const absolutePath = path.resolve(relativeOrAbsolutePathToPublicKey)
  const publicKey = fs.readFileSync(absolutePath, 'utf8')
  const buffer = Buffer.from(toEncrypt, 'utf8')
  const encrypted = crypto.publicEncrypt(publicKey, buffer)
  return encrypted.toString('base64')
}

function decrypt(toDecrypt, relativeOrAbsolutePathtoPrivateKey) {
  const absolutePath = path.resolve(relativeOrAbsolutePathtoPrivateKey)
  const privateKey = fs.readFileSync(absolutePath, 'utf8')
  const buffer = Buffer.from(toDecrypt, 'base64')
  const decrypted = crypto.privateDecrypt(
    {
      key: privateKey.toString(),
      passphrase: '',
    },
    buffer,
  )
  return decrypted.toString('utf8')
}


function generateKeyPair() {
  const init = new nodeRSA();
  return init.generateKeyPair(2048)
}

function encryptNodeRSA(toEncrypt, relativeOrAbsolutePathToPublicKey) {
  const absolutePath = path.join(__dirname, `./${relativeOrAbsolutePathToPublicKey}`)
  const publicKey = fs.readFileSync(absolutePath, 'utf8')

  let rsaPublic = new nodeRSA(publicKey)
  rsaPublic.setOptions({
    environment: 'browser',
    encryptionScheme: {
      scheme: 'pkcs1_oaep',
      hash: 'sha256',
      label: null,
    },
  })
  const buffer = Buffer.from(toEncrypt)
  const cipherText = rsaPublic.encrypt(buffer, 'base64')
  return cipherText
}

function decryptNodeRSA(toDecrypt, relativeOrAbsolutePathtoPrivateKey) {
  const absolutePath = path.join(__dirname, `./${relativeOrAbsolutePathtoPrivateKey}`)
  const privateKey = fs.readFileSync(absolutePath, 'utf8')

  let rsaPrivate = new nodeRSA(privateKey)
  rsaPrivate.setOptions({
    environment: 'browser',
    encryptionScheme: {
      scheme: 'pkcs1_oaep',
      hash: 'sha256',
      label: null,
    },
  })

  console.log(`\n toDecrypt ${toDecrypt} \n `)

  // const buffer = Buffer.from(toDecrypt, 'base64')
  const data = rsaPrivate.decrypt(toDecrypt, 'utf8')
  return data
}

module.exports = { generateKeys, encrypt, decrypt, encryptNodeRSA, decryptNodeRSA }

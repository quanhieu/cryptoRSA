const http = require('http');
const cryptoRsa = require('./cryptoRsa');

const hostname = '127.0.0.1';
const port = 3000;

const server = http.createServer((req, res) => {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/plain');
  res.end('Hello World');
});

function init() {
  cryptoRsa.generateKeys();
}

async function encrypt() {
  console.log(`\n start encrypt \n`);
  const dataEncrypt = {
    username: 'Hi1e2u',
    keygen: 'adad123413513tg13g246t42525r2gfegfkj3ijr3i09)#U*$Y(&EDHD(@E',
  }

  const encrypted = cryptoRsa.encrypt(`${JSON.stringify(dataEncrypt)}`, 'public_ras.pem')
  console.log(`\n encrypted ${encrypted}  \n`);
  return encrypted;
}

async function decrypt(encrypted) {
  console.log(`\n start decrypted \n`);
  const decrypted = cryptoRsa.decrypt(encrypted, 'private_rsa.pem')
  console.log(`\n decrypted ${decrypted}  \n`);
}

server.listen(port, hostname, async() => {
  console.log(`Server running at http://${hostname}:${port}/`);

  // init()

  const encrypted = await encrypt();
  
  decrypt(encrypted);
});

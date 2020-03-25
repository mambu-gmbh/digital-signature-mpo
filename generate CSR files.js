const fs = require('fs');
const jsrsasign = require('jsrsasign');

const kp = jsrsasign.KEYUTIL.generateKeypair("RSA", 2048);
const privateKey = kp.prvKeyObj;
const privateKeyPEM = jsrsasign.KEYUTIL.getPEM(privateKey, "PKCS8PRV");

var pem = jsrsasign.KJUR.asn1.csr.CSRUtil.newCSRPEM({
  subject: {str: '/C=US/O=ClearBankSign/CN=mambu.com'},
  sbjpubkey: kp.pubKeyObj,
  sigalg: "SHA256withRSA",
  sbjprvkey: privateKey
});

const keyInfo = jsrsasign.KJUR.asn1.csr.CSRUtil.getInfo(pem);
const rsaPublicKey = jsrsasign.hextob64(keyInfo.pubkey.hex);

// Store objects to files
fs.writeFile('certificate.csr', pem, (err) => { 
    if (err) throw err; 
})

fs.writeFile('public_key.pem', rsaPublicKey, (err) => { 
    if (err) throw err; 
})

fs.writeFile('private_key.pem', privateKeyPEM, (err) => { 
    if (err) throw err; 
})
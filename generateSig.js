const rs = require('jsrsasign');

kp = rs.KEYUTIL.generateKeypair("RSA", 2048);

pem = rs.KJUR.asn1.csr.CSRUtil.newCSRPEM({
  subject: {str: '/C=US/O=ClearBankSign/CN=mambu.com'},
  sbjpubkey: kp.pubKeyObj,
  sigalg: "SHA256withRSA",
  sbjprvkey: kp.prvKeyObj
});

var keyInfo = rs.KJUR.asn1.csr.CSRUtil.getInfo(pem);
var rsaKeyFromPEM = rs.KEYUTIL.getKeyFromCSRPEM(pem);
var rsaPrivateKey = rs.KEYUTIL.getKey(rsaKeyFromPEM);
var rsaPublicKey = rs.hextob64(keyInfo.pubkey.hex);

console.log("-----------");
console.log("CERTIFICATE:");
console.log(pem); // -----BEGIN CERTIFICATE REQUEST----- [...]

console.log("-----------");
console.log("PUBLIC KEY:");
console.log(rsaPublicKey);

//console.log("-----------");
//console.log("PRIVATE KEY:");
//console.log(kp.prvKeyObj); // or console.log(rs.KEYUTIL.getKey(kp.prvKeyObj));

//console.log("-----------");
//console.log("PRIVATE KEY AGAIN:");

var sig = new rs.KJUR.crypto.Signature({"alg": "SHA256withRSA"});

sig.init(kp.prvKeyObj);
sig.updateString('{"virtualAccounts":[{"ownerName":"test Client mari","accountIdentifier":{"iban":"GB32CLRB04062644624756"}}]}');

var hSigVal = sig.sign();
var sigBase64 = rs.hextob64(hSigVal);

console.log("-----------");
console.log("SIGNED MESSAGE:");
console.log(sigBase64);
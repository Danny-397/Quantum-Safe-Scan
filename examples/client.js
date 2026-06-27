// Example Node client using quantum-vulnerable cryptography (for demo purposes).
const crypto = require("crypto");
const tls = require("tls");

// HIGH: RSA key generation
const { publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 4096 });

// HIGH: MD5 hashing
const digest = crypto.createHash("md5").update("payload").digest("hex");

// MEDIUM: deprecated TLS 1.0
const ctx = tls.createSecureContext({ secureProtocol: "TLSv1_method" });

// LOW: AES-128
const cipher = crypto.createCipheriv("aes-128-gcm", key, iv);

module.exports = { publicKey, digest, ctx, cipher };

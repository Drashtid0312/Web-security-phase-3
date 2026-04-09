const crypto = require("crypto");

const algorithm = "aes-256-cbc";
const secretKey = crypto
  .createHash("sha256")
  .update(String(process.env.PROFILE_ENCRYPTION_KEY))
  .digest();

function encrypt(text) {
  if (!text) {
    return { encryptedData: "", iv: "" };
  }

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, secretKey, iv);

  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");

  return {
    encryptedData: encrypted,
    iv: iv.toString("hex"),
  };
}

function decrypt(encryptedData, iv) {
  if (!encryptedData || !iv) {
    return "";
  }

  const decipher = crypto.createDecipheriv(
    algorithm,
    secretKey,
    Buffer.from(iv, "hex")
  );

  let decrypted = decipher.update(encryptedData, "hex", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}

module.exports = { encrypt, decrypt };
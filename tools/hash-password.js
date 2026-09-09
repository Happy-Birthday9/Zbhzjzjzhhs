import crypto from "crypto";
const p=process.argv[2];
if(!p){console.error("Usage: node tools/hash-password.js YOUR_PASSWORD");process.exit(1)}
const salt=process.env.PASSWORD_SALT||"change-this-salt";
console.log(crypto.scryptSync(p,salt,32).toString("hex"));

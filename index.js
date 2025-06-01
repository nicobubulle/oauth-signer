const express = require("express");
const crypto = require("crypto");
const app = express();
const port = 3010;
app.use(express.json());

function percentEncode(str) {
  return encodeURIComponent(str)
    .replace(/\!/g, "%21")
    .replace(/\'/g, "%27")
    .replace(/\(/g, "%28")
    .replace(/\)/g, "%29")
    .replace(/\*/g, "%2A")
    .replace(/%7E/g, "~");
}

function generateNonce(length = 32) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let nonce = '';
  for (let i = 0; i < length; i++) {
    nonce += chars[Math.floor(Math.random() * chars.length)];
  }
  return nonce;
}

function getTimestamp() {
  return Math.floor(Date.now() / 1000).toString();
}

app.post("/sign", (req, res) => {
  const {
    url,
    method,
    consumerKey,
    consumerSecret,
    token,
    tokenSecret,
    params = {}
  } = req.body;

  if (!url || !method || !consumerKey || !consumerSecret || !token || !tokenSecret) {
    return res.status(400).json({ error: "Missing required parameters" });
  }

  const oauthParams = {
    oauth_consumer_key: consumerKey,
    oauth_token: token,
    oauth_nonce: generateNonce(),
    oauth_timestamp: getTimestamp(),
    oauth_signature_method: "HMAC-SHA1",
    oauth_version: "1.0"
  };

  const allParams = { ...params, ...oauthParams };

  const encodedParams = Object.keys(allParams)
    .sort()
    .map(key => `${percentEncode(key)}=${percentEncode(allParams[key])}`)
    .join("&");

  const baseString = [
    method.toUpperCase(),
    percentEncode(url.split("?")[0]),
    percentEncode(encodedParams)
  ].join("&");

  const signingKey = `${percentEncode(consumerSecret)}&${percentEncode(tokenSecret)}`;

  const hmac = crypto.createHmac("sha1", signingKey);
  hmac.update(baseString);
  const signature = hmac.digest("base64");

  oauthParams.oauth_signature = signature;

  const authHeader =
    "OAuth " +
    Object.keys(oauthParams)
      .sort()
      .map(key => `${percentEncode(key)}="${percentEncode(oauthParams[key])}"`)
      .join(", ");

  res.json({ Authorization: authHeader });
});

app.listen(port, () => {
  console.log(`OAuth 1 signer service listening at http://localhost:${port}`);
});

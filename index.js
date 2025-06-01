
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

app.use(bodyParser.json());

app.post('/sign', (req, res) => {
    const { baseString, signingKey } = req.body;

    if (!baseString || !signingKey) {
        return res.status(400).json({ error: 'Missing baseString or signingKey' });
    }

    try {
        const hmac = crypto.createHmac('sha1', signingKey);
        hmac.update(baseString);
        const signature = hmac.digest('base64');
        return res.json({ signature });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal error during signature' });
    }
});

app.listen(PORT, () => {
    console.log(`OAuth signature service running on port ${PORT}`);
});

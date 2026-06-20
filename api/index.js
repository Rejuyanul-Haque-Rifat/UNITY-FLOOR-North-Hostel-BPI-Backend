const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const admin = require('firebase-admin');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');

const app = express();

const allowedOrigins = ['https://bpi-blood-finder.firebaseapp.com', 'http://localhost:5173', 'http://127.0.0.1:5500'];
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}));

app.use(express.json());

const rpName = 'BPI Blood Finder';
const FRONTEND_ORIGIN = 'https://bpi-blood-finder.firebaseapp.com';

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n').replace(/"/g, '') : undefined,
    }),
    databaseURL: process.env.FIREBASE_DATABASE_URL
  });
}

const db = admin.database();

app.get('/', (req, res) => {
  res.send('BPI Blood Finder Backend is Secure & Running! 🚀');
});

app.post('/api/send-telegram', async (req, res) => {
  try {
    const { title, data } = req.body;
    const botToken = process.env.TG_BOT_TOKEN;
    const chatId = process.env.TG_USER_ID;
    
    if (!botToken || !chatId) return res.status(500).json({ error: 'Telegram credentials missing on server' });

    const message = `<b>${title}</b>\n\n<b>নাম:</b> ${data.name || 'অজ্ঞাত'}\n<b>ফোন:</b> ${data.contact || 'নেই'}\n<b>ম্যাসেজ:</b> ${data.text || ''}`;
    
    const tgRes = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, text: message, parse_mode: 'HTML' })
    });
    
    const tgData = await tgRes.json();
    res.json({ success: true, data: tgData });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/cloudinary-signature', (req, res) => {
  try {
    const timestamp = Math.round(new Date().getTime() / 1000);
    const apiSecret = process.env.CLOUDINARY_API_SECRET;
    
    if (!apiSecret) throw new Error("Cloudinary secret missing");

    const signatureString = `timestamp=${timestamp}${apiSecret}`;
    const signature = crypto.createHash('sha1').update(signatureString).digest('hex');
    
    res.json({ timestamp, signature });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/generate-registration-options', async (req, res) => {
  try {
    const { uid, email, name, rpID } = req.body;
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: uid,
      userName: email,
      userDisplayName: name,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'preferred',
      },
    });
    await db.ref(`passkey_challenges/${uid}`).set(options.challenge);
    res.json(options);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/verify-registration', async (req, res) => {
  try {
    const { uid, response, rpID } = req.body;
    const challengeSnap = await db.ref(`passkey_challenges/${uid}`).once('value');
    const expectedChallenge = challengeSnap.val();
    const expectedOrigin = req.headers.origin || FRONTEND_ORIGIN;
    
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
    });
    if (verification.verified) {
      const { registrationInfo } = verification;
      const { credentialPublicKey, credentialID, counter } = registrationInfo;
      const credentialIDBase64 = Buffer.from(credentialID).toString('base64url');
      const publicKeyBase64 = Buffer.from(credentialPublicKey).toString('base64url');
      const newPasskey = {
        credentialID: credentialIDBase64,
        credentialPublicKey: publicKeyBase64,
        counter,
        transports: response.response.transports || [],
        uid
      };
      await db.ref(`passkey_map/${credentialIDBase64}`).set(newPasskey);
      await db.ref(`passkey_challenges/${uid}`).remove();
      res.json({ verified: true });
    } else {
      res.status(400).json({ verified: false });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/generate-authentication-options', async (req, res) => {
  try {
    const { rpID } = req.body;
    const options = await generateAuthenticationOptions({
      rpID,
      userVerification: 'preferred',
    });
    await db.ref(`auth_challenges/${options.challenge}`).set(true);
    res.json(options);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/verify-authentication', async (req, res) => {
  try {
    const { response, expectedChallenge, rpID } = req.body;
    const challengeSnap = await db.ref(`auth_challenges/${expectedChallenge}`).once('value');
    if (!challengeSnap.exists()) {
      return res.status(400).json({ error: 'Invalid challenge' });
    }
    await db.ref(`auth_challenges/${expectedChallenge}`).remove();
    const credentialIDBase64 = response.id;
    const passkeySnap = await db.ref(`passkey_map/${credentialIDBase64}`).once('value');
    if (!passkeySnap.exists()) {
      return res.status(404).json({ error: 'Passkey not found' });
    }
    const passkey = passkeySnap.val();
    const expectedOrigin = req.headers.origin || FRONTEND_ORIGIN;

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialPublicKey: Buffer.from(passkey.credentialPublicKey, 'base64url'),
        credentialID: Buffer.from(passkey.credentialID, 'base64url'),
        counter: passkey.counter,
        transports: passkey.transports || [],
      },
    });
    if (verification.verified) {
      await db.ref(`passkey_map/${credentialIDBase64}`).update({
        counter: verification.authenticationInfo.newCounter
      });
      const customToken = await admin.auth().createCustomToken(passkey.uid);
      res.json({ verified: true, token: customToken });
    } else {
      res.status(400).json({ verified: false });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/update-user-email', async (req, res) => {
  try {
    const { uid, newEmail } = req.body;
    if (!uid || !newEmail) {
      return res.status(400).json({ error: 'Missing data' });
    }
    await admin.auth().updateUser(uid, { email: newEmail });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/admin-reset-pin', async (req, res) => {
  try {
    const { phone, newPin, adminSecret } = req.body;
    if (adminSecret !== process.env.ADMIN_SECRET) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (!phone || !newPin || phone.length !== 11 || newPin.length !== 4) {
      return res.status(400).json({ error: 'Invalid data' });
    }
    const snapshot = await db.ref('blood_donors').orderByChild('contact').equalTo(phone).once('value');
    if (!snapshot.exists()) {
      return res.status(404).json({ error: 'User not found' });
    }
    const userKey = Object.keys(snapshot.val())[0];
    const userData = snapshot.val()[userKey];
    const email = userData.email || `${phone}@bpi.com`;
    const newPassword = newPin + "00";
    let uid;
    try {
      const userRecord = await admin.auth().getUserByEmail(email);
      uid = userRecord.uid;
      await admin.auth().updateUser(uid, { password: newPassword });
    } catch (authError) {
      if (authError.code === 'auth/user-not-found') {
        const newUser = await admin.auth().createUser({
          email: email,
          password: newPassword,
          displayName: userData.name || 'BPI User'
        });
        uid = newUser.uid;
      } else {
        throw authError;
      }
    }
    await db.ref(`blood_donors/${userKey}`).update({ 
      uid: uid,
      password: newPassword 
    });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = app;

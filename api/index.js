require('dotenv').config();
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
app.use(cors());
app.use(express.json());

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n').replace(/"/g, '') : undefined,
    }),
    databaseURL: "https://unity-floor-north-hostel-bpi-default-rtdb.asia-southeast1.firebasedatabase.app"
  });
}

const db = admin.database();

app.get('/api/migrate-db', async (req, res) => {
  try {
    const snapshot = await db.ref('boarders').once('value');
    if (!snapshot.exists()) return res.json({ msg: 'No data' });
    res.json({ success: true, count: Object.keys(snapshot.val()).length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const rpName = 'UNITY FLOOR - North Hostel';

app.get('/', (req, res) => {
  res.send('UNITY FLOOR Backend is Running smoothly! 🚀');
});

app.post('/api/send-telegram', async (req, res) => {
  try {
    const { title, data } = req.body;
    const botToken = process.env.TG_BOT_TOKEN;
    const chatId = process.env.TG_USER_ID;
    
    if (!botToken || !chatId) return res.status(500).json({ error: 'Telegram credentials missing' });

    const message = req.body.text || `<b>${title}</b>\n\n<b>নাম:</b> ${data?.name || 'অজ্ঞাত'}\n<b>ফোন:</b> ${data?.contact || 'নেই'}\n<b>ম্যাসেজ:</b> ${data?.text || ''}`;
    
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    const tgRes = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, text: message, parse_mode: 'HTML' }),
        signal: controller.signal
    });
    
    clearTimeout(timeout);
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

app.post('/api/cloudinary-delete', async (req, res) => {
  try {
    const { public_id } = req.body;
    if (!public_id) {
      return res.status(400).json({ error: "public_id is required" });
    }

    const timestamp = Math.round(new Date().getTime() / 1000);
    const apiSecret = process.env.CLOUDINARY_API_SECRET;
    const apiKey = process.env.CLOUDINARY_API_KEY;
    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    
    if (!apiSecret || !apiKey || !cloudName) throw new Error("Cloudinary credentials missing");

    // Cloudinary requires signature with parameters sorted alphabetically
    const signatureString = `public_id=${public_id}&timestamp=${timestamp}${apiSecret}`;
    const signature = crypto.createHash('sha1').update(signatureString).digest('hex');
    
    const formData = new URLSearchParams();
    formData.append('public_id', public_id);
    formData.append('api_key', apiKey);
    formData.append('timestamp', timestamp);
    formData.append('signature', signature);

    const response = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/image/destroy`, {
      method: 'POST',
      body: formData
    });

    const data = await response.json();
    res.json(data);
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
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: req.headers.origin,
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
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: req.headers.origin,
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
    const customToken = await admin.auth().createCustomToken(uid);
    res.json({ success: true, token: customToken });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/admin-reset-pin', async (req, res) => {
  try {
    const { phone, newPin, adminSecret } = req.body;
    if (adminSecret !== "BPI_SECRET_123") {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (!phone || !newPin || phone.length !== 11 || newPin.length !== 6) {
      return res.status(400).json({ error: 'Invalid data' });
    }
    let uid = null;
    let email = `${phone}@bpi.com`;
    let displayName = 'Unity Boarder';

    const lookupSnap = await db.ref(`user_lookup/${phone}`).once('value');
    if (lookupSnap.exists()) {
      const lookup = lookupSnap.val();
      if (lookup.uid) uid = lookup.uid;
      if (lookup.email) email = lookup.email;
    }

    if (!uid) {
      const snapshot = await db.ref('boarders').orderByChild('contact').equalTo(phone).once('value');
      if (snapshot.exists()) {
        const userKey = Object.keys(snapshot.val())[0];
        const userData = snapshot.val()[userKey];
        uid = userData.uid || userKey;
        if (userData.email) email = userData.email;
        if (userData.name) displayName = userData.name;
      }
    }

    if (!uid) {
      return res.status(404).json({ error: 'User not found' });
    }

    const newPassword = newPin;
    try {
      await admin.auth().updateUser(uid, { password: newPassword });
    } catch (authError) {
      if (authError.code === 'auth/user-not-found') {
        const newUser = await admin.auth().createUser({
          uid,
          email,
          password: newPassword,
          displayName
        });
        uid = newUser.uid;
      } else {
        throw authError;
      }
    }
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- START SECURE AUTH ENDPOINTS ---
app.post('/api/register', async (req, res) => {
  try {
    const { contact, pin, name, room, department, session, semester, status, photoUrl, bio, hideContact, hidePhoto } = req.body;
    
    if (!contact || !pin || contact.length !== 11 || pin.length !== 6) {
      return res.status(400).json({ error: 'Invalid phone or PIN format' });
    }

    const email = `${contact}@bpi.com`;
    const password = pin;

    const lookupSnap = await db.ref(`user_lookup/${contact}`).once('value');
    if (lookupSnap.exists()) {
      return res.status(409).json({ error: 'এই ফোন নাম্বার দিয়ে ইতিমধ্যে একটি অ্যাকাউন্ট রয়েছে' });
    }
    
    let uid;
    try {
      const userRecord = await admin.auth().createUser({
        email,
        password,
        displayName: name
      });
      uid = userRecord.uid;
    } catch (authErr) {
      if (authErr.code === 'auth/email-already-exists') {
        return res.status(409).json({ error: 'এই ফোন নাম্বার দিয়ে ইতিমধ্যে একটি অ্যাকাউন্ট রয়েছে' });
      }
      throw authErr;
    }

    const updates = {};
    updates[`boarders/${uid}`] = {
      id: uid,
      uid,
      email,
      name: name || '',
      contact,
      phoneNumber: contact,
      room: room || '301',
      department: department || '',
      session: session || '',
      semester: semester || '',
      batch: session || '2023-24',
      status: status || 'current',
      photoUrl: photoUrl || '',
      bio: bio || '',
      hideContact: Boolean(hideContact),
      hidePhoto: Boolean(hidePhoto),
      joinedAt: new Date().toISOString(),
      updatedAt: Date.now()
    };
    updates[`user_lookup/${contact}`] = { uid, email };
    
    try {
      await db.ref().update(updates);
    } catch (dbErr) {
      await admin.auth().deleteUser(uid).catch(() => {});
      throw dbErr;
    }
    
    const customToken = await admin.auth().createCustomToken(uid);
    res.json({ success: true, token: customToken, uid });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const loginAttempts = {};

app.post('/api/login', async (req, res) => {
  try {
    const { contact, pin } = req.body;
    
    if (!contact || !pin || pin.length !== 6) {
      return res.status(400).json({ error: 'Missing or invalid credentials' });
    }
    
    const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
    const now = Date.now();
    if (loginAttempts[ip] && loginAttempts[ip].count >= 10 && (now - loginAttempts[ip].timestamp) < 15 * 60 * 1000) {
      return res.status(429).json({ error: 'Too many attempts. Please try again after 15 minutes.' });
    }
    
    let email = `${contact}@bpi.com`;
    const lookupSnap = await db.ref(`user_lookup/${contact}`).once('value');
    if (lookupSnap.exists() && lookupSnap.val().email) {
      email = lookupSnap.val().email;
    } else {
       const boardersSnap = await db.ref('boarders').orderByChild('contact').equalTo(contact).once('value');
       if (boardersSnap.exists()) {
         const firstKey = Object.keys(boardersSnap.val())[0];
         if (boardersSnap.val()[firstKey].email) {
           email = boardersSnap.val()[firstKey].email;
         }
       }
    }

    const password = pin;
    const apiKey = process.env.FIREBASE_WEB_API_KEY;
    
    if (!apiKey) {
      return res.status(500).json({ error: 'Server misconfiguration: FIREBASE_WEB_API_KEY missing' });
    }

    const response = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        password,
        returnSecureToken: true
      })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      if (!loginAttempts[ip]) loginAttempts[ip] = { count: 0, timestamp: now };
      loginAttempts[ip].count += 1;
      loginAttempts[ip].timestamp = now;
      
      return res.status(401).json({ error: 'ফোন নাম্বার অথবা পিন সঠিক নয়' });
    }
    
    if (loginAttempts[ip]) delete loginAttempts[ip];
    
    const uid = data.localId;
    const customToken = await admin.auth().createCustomToken(uid);
    
    res.json({ success: true, token: customToken, uid });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
// --- END SECURE AUTH ENDPOINTS ---

app.post('/api/delete-user', async (req, res) => {
  try {
    const { uid, email, adminSecret } = req.body;
    if (adminSecret !== "BPI_SECRET_123") {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (!uid && !email) {
      return res.status(400).json({ error: 'Missing user identifier (uid or email)' });
    }
    
    let targetUid = uid;
    if (!targetUid && email) {
      try {
        const userRecord = await admin.auth().getUserByEmail(email);
        targetUid = userRecord.uid;
      } catch (authError) {
        if (authError.code === 'auth/user-not-found') {
          return res.json({ success: true, message: 'User already deleted' });
        }
        throw authError;
      }
    }
    
    if (targetUid) {
      await admin.auth().deleteUser(targetUid);
      return res.json({ success: true, message: 'User auth deleted successfully' });
    } else {
      return res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const zlib = require('zlib');
const util = require('util');
const brotliCompress = util.promisify(zlib.brotliCompress);

app.get('/api/boarders/full-dump', async (req, res) => {
  try {
    const snapshot = await db.ref('boarders').once('value');
    const data = snapshot.val() || {};
    
    const jsonString = JSON.stringify(data);
    const compressed = await brotliCompress(jsonString, {
      params: {
        [zlib.constants.BROTLI_PARAM_QUALITY]: 4,
      }
    });

    res.setHeader('Cache-Control', 'public, s-maxage=3600, stale-while-revalidate=86400');
    res.setHeader('Content-Encoding', 'br');
    res.setHeader('Content-Type', 'application/json');
    
    res.send(compressed);
  } catch (error) {
    console.error('Full dump error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/boarders/delta', async (req, res) => {
  try {
    const { since } = req.query;
    if (!since) {
      return res.status(400).json({ error: 'Missing "since" timestamp' });
    }

    const timestamp = parseInt(since, 10);
    
    const snapshot = await db.ref('boarders')
      .orderByChild('updatedAt')
      .startAt(timestamp)
      .once('value');
      
    const data = snapshot.val() || {};
    res.json(data);
  } catch (error) {
    console.error('Delta fetch error:', error);
    res.status(500).json({ error: error.message });
  }
});

// --- START NOTIFICATION ENDPOINTS ---
app.post('/api/notifications/subscribe', async (req, res) => {
  try {
    const { token, topic = 'all_users' } = req.body;
    if (!token) {
      return res.status(400).json({ error: 'FCM Token is required' });
    }
    
    // Subscribe the token to the given topic
    await admin.messaging().subscribeToTopic([token], topic);
    res.json({ success: true, message: `Successfully subscribed to topic: ${topic}` });
  } catch (error) {
    console.error('Subscription error:', error);
    res.status(500).json({ error: error.message });
  }
});


app.post('/api/notifications/unsubscribe', async (req, res) => {
  try {
    const { token, topic } = req.body;
    if (!token || !topic) {
      return res.status(400).json({ error: 'FCM Token and topic are required' });
    }
    
    await admin.messaging().unsubscribeFromTopic([token], topic);
    res.json({ success: true, message: `Successfully unsubscribed from topic: ${topic}` });
  } catch (error) {
    console.error('Unsubscription error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/notifications/send', async (req, res) => {
  try {
    const { title, body, image, mode = 'bulk', specificTarget, target, scheduleTime, adminSecret, clickAction = '/notice' } = req.body;
    
    if (adminSecret !== "BPI_SECRET_123") {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    if (!title || !body) {
      return res.status(400).json({ error: 'Title and body are required' });
    }

    const cleanBody = body
      .replace(/&amp;nbsp;/gi, ' ')
      .replace(/&nbsp;/gi, ' ')
      .replace(/&#160;/gi, ' ')
      .trim();

    let targetTopic = 'all_users';
    const effectiveTarget = specificTarget || target;
    if (mode === 'specific' && effectiveTarget) {
      targetTopic = effectiveTarget;
    }
    
    const isScheduled = Boolean(scheduleTime && new Date(scheduleTime).getTime() > Date.now());

    if (isScheduled) {
      await db.ref('scheduled_notifications').push({
        title,
        body: cleanBody,
        image: image || null,
        mode,
        targetTopic,
        scheduleTime,
        clickAction,
        createdAt: Date.now(),
        status: 'scheduled'
      });
      return res.json({ success: true, scheduled: true, message: 'Notification scheduled successfully' });
    }

    const message = {
      topic: targetTopic,
      notification: {
        title,
        body: cleanBody,
        ...(image && { image })
      },
      data: {
        title,
        body: cleanBody,
        ...(image && { image }),
        clickAction: clickAction || '/notice',
        url: clickAction || '/notice'
      },
      android: {
        priority: 'high',
        notification: {
          sound: 'default',
          clickAction: clickAction || '/notice'
        }
      },
      webpush: {
        headers: {
          Urgency: 'high',
          urgency: 'high',
          TTL: '86400'
        },
        notification: {
          requireInteraction: true,
          vibrate: [200, 100, 200, 100, 200, 100, 200]
        },
        fcmOptions: {
          link: clickAction || '/notice'
        }
      }
    };
    
    const response = await admin.messaging().send(message);
    res.json({ success: true, messageId: response });
  } catch (error) {
    console.error('Notification send error:', error);
    res.status(500).json({ error: error.message });
  }
});
// --- END NOTIFICATION ENDPOINTS ---

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {});
module.exports = app;

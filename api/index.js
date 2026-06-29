const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const admin = require('firebase-admin');
const { Resend } = require('resend');
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
    databaseURL: "https://bpi-blood-finder-default-rtdb.firebaseio.com"
  });
}

const db = admin.database();
const rpName = 'BPI Blood Finder';
const resend = new Resend(process.env.RESEND_API_KEY);

app.get('/', (req, res) => {
  res.send('BPI Blood Finder Backend is Running smoothly! 🚀');
});

app.post('/api/send-reset-email', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const actionCodeSettings = {
      url: 'https://bpi-blood-finder.web.app/reset-password-set',
      handleCodeInApp: true
    };
    
    const resetLink = await admin.auth().generatePasswordResetLink(email, actionCodeSettings);

    const emailHtml = `
<!DOCTYPE html>
<html lang="bn">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f4f7f6; font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased;">
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f4f7f6; padding: 10px 5px;">
        <tr>
            <td align="center">
                <table width="100%" max-width="600" cellpadding="0" cellspacing="0" border="0" style="max-width: 600px; width: 100%; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.05);">
                    <tr>
                        <td align="center" style="background-color: #dc3545; padding: 15px 10px; border-bottom: 4px solid #b02a37;">
                            <img src="https://bpi-blood-finder.web.app/favicon.png" alt="BPI Logo" style="width: 45px; height: 45px; vertical-align: middle;">
                            <span style="color: #ffffff; font-size: 18px; font-weight: 800; vertical-align: middle; margin-left: 8px; display: inline-block; letter-spacing: 0.5px;">BPI BLOOD FINDER</span>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 20px 15px; color: #374151; line-height: 1.5; font-size: 15px;">
                            <p style="margin-top: 0; font-size: 16px; font-weight: 600; color: #1f2937;">আসসালামু আলাইকুম,</p>
                            <p style="margin-bottom: 20px; text-align: justify;">আমরা আপনার <strong>BPI BLOOD FINDER</strong> অ্যাকাউন্টের পাসওয়ার্ড রিসেট করার একটি অনুরোধ পেয়েছি। আপনি যদি এই অনুরোধটি করে থাকেন, তবে নিচের বাটনে ক্লিক করে আপনার নতুন পাসওয়ার্ড সেট করুন</p>
                            <div style="text-align: center; margin: 25px 0;">
                                <a href="${resetLink}" style="background-color: #1877f2; color: #ffffff; padding: 12px 25px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px; display: inline-block; box-shadow: 0 4px 10px rgba(24,119,242,0.3); transition: background-color 0.3s;">পাসওয়ার্ড রিসেট করুন</a>
                            </div>
                            <p style="font-size: 13px; color: #6b7280; margin-bottom: 25px; text-align: justify; line-height: 1.4;"><strong>সতর্কতা:</strong> আপনি যদি পাসওয়ার্ড রিসেট করার অনুরোধ না করে থাকেন, তবে এই ইমেইলটি এড়িয়ে যান। আপনার অ্যাকাউন্ট সম্পূর্ণ নিরাপদ আছে ।</p>
                            <p style="margin: 0; font-size: 14px; color: #4b5563;">ধন্যবাদান্তে,<br><span style="color: #dc3545; font-weight: bold; font-size: 16px; margin-top: 5px; display: inline-block;">BPI BLOOD FINDER</span></p>
                        </td>
                    </tr>
                    <tr>
                        <td align="center" style="background-color: #f8f9fa; padding: 20px 15px; border-top: 1px solid #e5e7eb;">
                            <p style="color: #6b7280; font-size: 13px; margin: 0 0 5px 0; font-weight: 700;">Developed & Maintenance by :</p>
                            <p style="color: #1877f2; font-size: 18px; margin: 0; font-weight: 900; letter-spacing: 0.5px;">Rejuyanul Haque Rifat</p>
                        </td>
                    </tr>
                </table>
                <table width="100%" cellpadding="0" cellspacing="0" border="0">
                    <tr><td height="30">&nbsp;</td></tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
    `;

    const data = await resend.emails.send({
      from: process.env.RESEND_FROM_EMAIL || 'BPI Blood Finder <onboarding@resend.dev>',
      to: email,
      subject: 'পাসওয়ার্ড রিসেট করুন - BPI Blood Finder',
      html: emailHtml
    });

    if (data.error) {
      return res.status(400).json({ error: data.error.message });
    }

    res.json({ success: true, message: "Password reset email sent." });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/send-telegram', async (req, res) => {
  try {
    const { title, data } = req.body;
    const botToken = process.env.TG_BOT_TOKEN;
    const chatId = process.env.TG_USER_ID;
    
    if (!botToken || !chatId) return res.status(500).json({ error: 'Telegram credentials missing' });

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
    res.json({ success: true });
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {});
module.exports = app;

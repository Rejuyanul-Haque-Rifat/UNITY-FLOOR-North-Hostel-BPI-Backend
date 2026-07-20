require('dotenv').config();
const admin = require('firebase-admin');

admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n').replace(/"/g, '') : undefined,
  }),
  databaseURL: 'https://bpi-blood-finder-default-rtdb.firebaseio.com'
});

const db = admin.database();

async function migrate() {
  const snapshot = await db.ref('blood_donors').once('value');
  const donors = snapshot.val();
  const donorsIndex = {};
  
  for (const [id, data] of Object.entries(donors)) {
    donorsIndex[id] = {
      n: data.name || '', bg: data.bloodGroup || '',
      a: data.address || '', ld: data.lastDonation || '',
      dc: data.donationCount || 0, p: data.photoUrl || '',
      hp: data.hidePhoto || false, hc: data.hideContact || false,
      v: data.isVerified || false, u: data.updatedAt || Date.now(),
      d: data.deleted || false, c: data.hideContact ? '' : (data.contact || '')
    };
  }
  
  await db.ref('donors_index').set(donorsIndex);
  console.log('Migration complete. Checking one record...');
  const check = await db.ref('donors_index').orderByKey().limitToFirst(1).once('value');
  console.log(check.val());
  process.exit(0);
}

migrate().catch(console.error);

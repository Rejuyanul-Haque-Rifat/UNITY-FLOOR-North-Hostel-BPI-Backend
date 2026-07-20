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

async function run() {
  await db.ref('blood_donors/-O23eJ10tH4Z_C5FvW-P').update({ contact: '01522138626' });
  console.log('Donor contact restored.');
  
  await db.ref('auth_challenges').remove();
  console.log('auth_challenges cleared.');
  process.exit(0);
}
run();
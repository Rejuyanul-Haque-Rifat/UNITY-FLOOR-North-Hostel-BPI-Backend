const admin = require('firebase-admin');

// Load environment variables for local testing if needed
require('dotenv').config();

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

async function migrateDatabase() {
  console.log("Starting database migration...");
  try {
    const snapshot = await db.ref('blood_donors').once('value');
    if (!snapshot.exists()) {
      console.log("No blood_donors found.");
      return;
    }
    
    const donors = snapshot.val();
    const donorsIndex = {};
    const donorsPrivate = {};
    const donorsByGroup = {};

    for (const [id, data] of Object.entries(donors)) {
      // Create minified index
      donorsIndex[id] = {
        n: data.name || '',
        bg: data.bloodGroup || '',
        a: data.address || '',
        ld: data.lastDonation || '',
        dc: data.donationCount || 0,
        p: data.photoUrl || '',
        hp: data.hidePhoto || false,
        hc: data.hideContact || false,
        v: data.isVerified || false,
        u: data.updatedAt || Date.now(),
        d: data.deleted || false
      };

      // Create private data
      donorsPrivate[id] = {
        contact: data.contact || '',
        email: data.email || '',
        uid: data.uid || ''
      };

      // Shard by blood group for server-side pagination (P3 future-proofing)
      if (data.bloodGroup && !data.deleted) {
        const safeGroup = data.bloodGroup.replace('+', '_PLUS').replace('-', '_MINUS');
        if (!donorsByGroup[safeGroup]) donorsByGroup[safeGroup] = {};
        donorsByGroup[safeGroup][id] = data.updatedAt || Date.now();
      }
    }

    console.log(`Prepared ${Object.keys(donorsIndex).length} records for migration.`);

    // Perform atomic update to apply new structures
    const updates = {
      'donors_index': donorsIndex,
      'donors_private': donorsPrivate,
      'donors_by_group': donorsByGroup
    };

    console.log("Writing to Firebase...");
    await db.ref().update(updates);
    
    console.log("Migration completed successfully!");
    process.exit(0);
  } catch (error) {
    console.error("Migration failed:", error);
    process.exit(1);
  }
}

migrateDatabase();

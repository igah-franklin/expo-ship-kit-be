const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/expo-ship-kit';

function signAscJwt(p8Content, keyId, issuerId) {
  return jwt.sign(
    {
      iss: issuerId,
      exp: Math.floor(Date.now() / 1000) + 1200,
      aud: 'appstoreconnect-v1'
    },
    p8Content,
    { algorithm: 'ES256', header: { alg: 'ES256', kid: keyId, typ: 'JWT' } }
  );
}

mongoose.connect(mongoUri)
  .then(async () => {
    // We define a schema that matches our DB
    const Build = mongoose.model('Build', new mongoose.Schema({
      bundleIdentifier: String,
      logs: [String],
      createdAt: Date
    }));

    // Find the last build
    const build = await Build.findOne().sort({ createdAt: -1 });
    if (!build) {
      console.log('No builds found.');
      await mongoose.connection.close();
      process.exit(0);
    }

    // Now, we need the credentials. Since credentials are not stored on the Build model directly
    // but passed to runBuild (which reads them from the request/session/form payload),
    // let's check if the credentials are saved anywhere, or if we can extract them.
    // Wait, let's check what fields are stored in the Build schema in index.ts or buildService.ts.
    // Let's print the build keys first.
    console.log('Build document:', JSON.stringify(build, null, 2));

    await mongoose.connection.close();
    process.exit(0);
  })
  .catch(err => {
    console.error('Error:', err);
    process.exit(1);
  });

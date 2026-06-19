import express from 'express';
import multer from 'multer';
import fs from 'fs';
import Build from '../models/Build';
import { runBuild } from '../services/buildService';

const router = express.Router();

// Setup multer for uploading ZIP file and .p8 developer key
const upload = multer({ dest: 'uploads/' });

// Mask token for DB storage
function maskToken(token: string): string {
  if (!token) return '';
  if (token.length <= 8) return '********';
  return `${token.substring(0, 4)}...${token.substring(token.length - 4)}`;
}

// 1. GET /api/builds - List build history
router.get('/', async (req, res) => {
  try {
    const builds = await Build.find().sort({ createdAt: -1 }).limit(50);
    return res.json({ success: true, builds });
  } catch (error) {
    return res.status(500).json({ success: false, message: (error as Error).message });
  }
});

// 2. GET /api/builds/:id - Get specific build status and logs
router.get('/:id', async (req, res) => {
  try {
    const build = await Build.findById(req.params.id);
    if (!build) {
      return res.status(404).json({ success: false, message: 'Build not found.' });
    }
    return res.json({ success: true, build });
  } catch (error) {
    return res.status(500).json({ success: false, message: (error as Error).message });
  }
});

// 3. POST /api/builds - Upload files and trigger new build
router.post(
  '/',
  upload.fields([
    { name: 'project', maxCount: 1 },
    { name: 'appleKey', maxCount: 1 }
  ]),
  async (req, res) => {
    try {
      const files = req.files as { [fieldname: string]: Express.Multer.File[] };
      const { expoToken, issuerId, keyId, appleTeamId, customBundleId, appleTeamType } = req.body;

      // Validate files
      if (!files || !files.project || files.project.length === 0) {
        return res.status(400).json({ success: false, message: 'Missing project ZIP folder upload.' });
      }
      if (!files.appleKey || files.appleKey.length === 0) {
        return res.status(400).json({ success: false, message: 'Missing Apple admin key (.p8) file.' });
      }

      // Validate form inputs
      if (!expoToken) {
        return res.status(400).json({ success: false, message: 'Missing Expo token.' });
      }
      if (!issuerId) {
        return res.status(400).json({ success: false, message: 'Missing Issuer ID.' });
      }
      if (!keyId) {
        return res.status(400).json({ success: false, message: 'Missing Apple Key ID.' });
      }
      if (!appleTeamId) {
        return res.status(400).json({ success: false, message: 'Missing Apple Team ID.' });
      }

      const projectFile = files.project[0];
      const appleKeyFile = files.appleKey[0];

      // Read Apple Key (.p8 file) contents
      const p8KeyContent = fs.readFileSync(appleKeyFile.path, 'utf8');

      // Clean up the temporary uploaded key file immediately from backend uploads directory
      try {
        fs.unlinkSync(appleKeyFile.path);
      } catch (err) {
        console.error('Failed to unlink temp uploaded key file:', err);
      }

      // Create initial build record in MongoDB
      const build = new Build({
        projectName: 'Preparing...',
        slug: 'preparing',
        bundleIdentifier: customBundleId || 'Checking...',
        status: 'pending',
        logs: ['Received upload. Initializing build pipeline...'],
        expoTokenMasked: maskToken(expoToken)
      });

      await build.save();

      // Trigger build service asynchronously
      runBuild(
        build._id.toString(),
        projectFile.path,
        expoToken,
        p8KeyContent,
        issuerId,
        keyId,
        appleTeamId,
        customBundleId,
        appleTeamType || 'COMPANY_OR_ORGANIZATION'
      ).catch((err) => {
        console.error(`Error in runBuild async promise for build ${build._id}:`, err);
      });

      return res.status(201).json({
        success: true,
        message: 'Build pipeline triggered successfully.',
        build
      });

    } catch (error) {
      return res.status(500).json({ success: false, message: (error as Error).message });
    }
  }
);

export default router;

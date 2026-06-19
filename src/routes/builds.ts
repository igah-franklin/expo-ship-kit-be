import express from 'express';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import AdmZip from 'adm-zip';
import Build from '../models/Build';
import { runBuild, validateExpoToken, validateAppleCredentials } from '../services/buildService';

const router = express.Router();

// Setup multer for uploading ZIP file and .p8 developer key
const upload = multer({ dest: 'uploads/' });

// Mask token for DB storage
function maskToken(token: string): string {
  if (!token) return '';
  if (token.length <= 8) return '********';
  return `${token.substring(0, 4)}...${token.substring(token.length - 4)}`;
}

// Helper to clone and zip a GitHub repo
async function cloneAndZipRepo(githubUrl: string, branch: string, destZipPath: string): Promise<string> {
  const tempCloneDir = path.join(__dirname, '../../temp', `clone-${Date.now()}`);
  if (!fs.existsSync(path.dirname(tempCloneDir))) {
    fs.mkdirSync(path.dirname(tempCloneDir), { recursive: true });
  }

  return new Promise<string>((resolve, reject) => {
    const cloneArgs = ['clone', '--single-branch', '--depth', '1'];
    if (branch && branch.trim()) {
      cloneArgs.push('--branch', branch.trim());
    }
    cloneArgs.push(githubUrl, tempCloneDir);

    const gitProc = spawn('git', cloneArgs);
    let errOutput = '';
    gitProc.stderr.on('data', (data) => {
      errOutput += data.toString();
    });
    gitProc.on('close', (code) => {
      if (code !== 0) {
        return reject(new Error(`Git clone failed with code ${code}. Details: ${errOutput}`));
      }

      // Zip the folder
      try {
        const zip = new AdmZip();
        const files = fs.readdirSync(tempCloneDir);
        for (const file of files) {
          if (file === '.git') continue;
          const fullPath = path.join(tempCloneDir, file);
          const stat = fs.statSync(fullPath);
          if (stat.isDirectory()) {
            zip.addLocalFolder(fullPath, file);
          } else {
            zip.addLocalFile(fullPath);
          }
        }
        zip.writeZip(destZipPath);

        // Cleanup cloned dir in background
        fs.rm(tempCloneDir, { recursive: true, force: true }, () => {});
        resolve(tempCloneDir.split(path.sep).pop() || 'Repo');
      } catch (zipErr: any) {
        reject(new Error(`Failed to zip cloned repository: ${zipErr.message}`));
      }
    });
  });
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

// 3. POST /api/builds/validate-expo-token - Validate Expo access token
router.post('/validate-expo-token', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ success: false, message: 'Expo token is required.' });
    }
    const check = await validateExpoToken(token);
    if (!check.valid) {
      return res.status(400).json({ success: false, message: check.error || 'Token validation failed.' });
    }
    return res.json({ success: true, username: check.username });
  } catch (error) {
    return res.status(500).json({ success: false, message: (error as Error).message });
  }
});

// 4. POST /api/builds/validate-apple - Validate Apple API developer keys
router.post('/validate-apple', upload.single('appleKey'), async (req, res) => {
  try {
    const file = req.file;
    const { issuerId, keyId, appleTeamId } = req.body;
    if (!file) {
      return res.status(400).json({ success: false, message: 'Missing Apple developer key (.p8) file.' });
    }
    if (!issuerId || !keyId || !appleTeamId) {
      return res.status(400).json({ success: false, message: 'Issuer ID, Key ID, and Team ID are required.' });
    }

    const p8KeyContent = fs.readFileSync(file.path, 'utf8');
    try { fs.unlinkSync(file.path); } catch {}

    const check = await validateAppleCredentials(issuerId, keyId, p8KeyContent);
    if (!check.valid) {
      return res.status(400).json({ success: false, message: check.error || 'Apple credentials validation failed.' });
    }
    return res.json({ success: true });
  } catch (error) {
    return res.status(500).json({ success: false, message: (error as Error).message });
  }
});

// 5. POST /api/builds - Upload files or use GitHub repo URL and trigger new build
router.post(
  '/',
  upload.fields([
    { name: 'project', maxCount: 1 },
    { name: 'appleKey', maxCount: 1 }
  ]),
  async (req, res) => {
    try {
      const files = req.files as { [fieldname: string]: Express.Multer.File[] };
      const { expoToken, issuerId, keyId, appleTeamId, customBundleId, appleTeamType, githubUrl, githubBranch } = req.body;

      const hasProjectFile = files && files.project && files.project.length > 0;
      if (!hasProjectFile && !githubUrl) {
        return res.status(400).json({ success: false, message: 'Missing project ZIP folder upload or GitHub URL.' });
      }
      if (!files || !files.appleKey || files.appleKey.length === 0) {
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

      const appleKeyFile = files.appleKey[0];
      const p8KeyContent = fs.readFileSync(appleKeyFile.path, 'utf8');
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
        logs: ['Received build request. Initializing build pipeline...'],
        expoTokenMasked: maskToken(expoToken)
      });

      await build.save();

      // Trigger build service asynchronously
      (async () => {
        let localZipPath = '';
        try {
          if (githubUrl) {
            await Build.findByIdAndUpdate(build._id, { $push: { logs: `Cloning GitHub repository: ${githubUrl} (branch: ${githubBranch || 'default'})...` } });
            localZipPath = path.join(__dirname, '../../uploads', `github-${build._id}.zip`);
            const repoName = await cloneAndZipRepo(githubUrl, githubBranch, localZipPath);
            await Build.findByIdAndUpdate(build._id, { 
              projectName: repoName,
              slug: repoName.toLowerCase().replace(/[\W_]+/g, '-'),
              $push: { logs: 'Successfully cloned and packaged GitHub repository.' } 
            });
          } else {
            localZipPath = files.project[0].path;
          }

          await runBuild(
            build._id.toString(),
            localZipPath,
            expoToken,
            p8KeyContent,
            issuerId,
            keyId,
            appleTeamId,
            customBundleId,
            appleTeamType || 'COMPANY_OR_ORGANIZATION'
          );
        } catch (err: any) {
          console.error(`Error in runBuild async process:`, err);
          await Build.findByIdAndUpdate(build._id, { 
            status: 'failed',
            $push: { logs: `Build pipeline failed: ${err.message}` } 
          });
        }
      })();

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

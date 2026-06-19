import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import AdmZip from 'adm-zip';
import jwt from 'jsonwebtoken';
import Build from '../models/Build';

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Recursively find the directory containing app.json / app.config.js */
function findProjectRoot(dir: string): string {
  if (
    fs.existsSync(path.join(dir, 'app.json')) ||
    fs.existsSync(path.join(dir, 'app.config.js')) ||
    fs.existsSync(path.join(dir, 'app.config.ts'))
  ) {
    return dir;
  }

  const files = fs.readdirSync(dir);
  for (const file of files) {
    const fullPath = path.join(dir, file);
    if (fs.statSync(fullPath).isDirectory()) {
      if (file === 'node_modules' || file === '.git' || file === '.expo') {
        continue;
      }
      const found = findProjectRoot(fullPath);
      if (found) return found;
    }
  }
  return dir;
}

/** Spawn a process and collect output, with optional timeout */
function spawnAsync(
  cmd: string,
  args: string[],
  opts: { cwd: string; env: Record<string, string | undefined>; timeoutMs?: number },
  onData?: (data: string) => void
): Promise<{ success: boolean; output: string }> {
  return new Promise((resolve) => {
    const proc = spawn(cmd, args, {
      cwd: opts.cwd,
      env: opts.env,
      shell: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let output = '';
    proc.stdout?.on('data', (d: Buffer) => {
      const s = d.toString();
      output += s;
      onData?.(s);
    });
    proc.stderr?.on('data', (d: Buffer) => {
      const s = d.toString();
      output += s;
      onData?.(s);
    });
    proc.on('close', (code) => resolve({ success: code === 0, output }));

    const timeout = opts.timeoutMs || 120000;
    setTimeout(() => {
      proc.kill();
      resolve({ success: false, output: output + '\nTimeout: command exceeded time limit' });
    }, timeout);
  });
}

/** Validate Expo token via GraphQL API and return username */
export async function validateExpoToken(
  token: string
): Promise<{ valid: boolean; username?: string; error?: string }> {
  try {
    const res = await fetch('https://api.expo.dev/graphql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ query: '{ me { username } }' }),
    });
    const data: any = await res.json();
    if (data?.errors?.length) {
      return { valid: false, error: data.errors[0]?.message || 'Invalid token' };
    }
    const username = data?.data?.me?.username;
    if (!username) return { valid: false, error: 'Could not fetch Expo account — token may be invalid' };
    return { valid: true, username };
  } catch (err: any) {
    return { valid: false, error: `Network error reaching Expo: ${err.message}` };
  }
}

/** Validate Apple Developer credentials by signing a test JWT and hitting ConnectAPI */
export async function validateAppleCredentials(
  issuerId: string,
  keyId: string,
  p8KeyContent: string
): Promise<{ valid: boolean; error?: string }> {
  try {
    const jwtToken = signAscJwt({ p8Content: p8KeyContent, keyId, issuerId });
    const res = await fetch('https://api.appstoreconnect.apple.com/v1/bundleIds?limit=1', {
      headers: { Authorization: `Bearer ${jwtToken}` }
    });
    if (!res.ok) {
      const text = await res.text();
      return { valid: false, error: `Apple API returned HTTP ${res.status}: ${text.slice(0, 300)}` };
    }
    return { valid: true };
  } catch (err: any) {
    return { valid: false, error: `Apple ASC Key Authentication failed: ${err.message}` };
  }
}

// ─── Apple Local Provisioning Helpers ────────────────────────────────────────

/** Sign an App Store Connect JWT with the user-uploaded .p8 */
function signAscJwt(ascApiKey: { p8Content: string; keyId: string; issuerId: string }): string {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    { iss: ascApiKey.issuerId, iat: now, exp: now + 20 * 60, aud: 'appstoreconnect-v1' },
    ascApiKey.p8Content,
    { algorithm: 'ES256', header: { alg: 'ES256', kid: ascApiKey.keyId, typ: 'JWT' } as any }
  );
}

/** Generate private key and CSR locally using openssl */
async function generateKeyAndCsr(dir: string): Promise<{ privateKeyPath: string; csrPath: string }> {
  const rawPrivateKeyPath = path.join(dir, 'temp_private.key');
  const rawCsrPath = path.join(dir, 'temp_request.csr');

  const privateKeyPath = `"${rawPrivateKeyPath}"`;
  const csrPath = `"${rawCsrPath}"`;

  // Generate private key
  const genKey = await spawnAsync('openssl', ['genrsa', '-out', privateKeyPath, '2048'], {
    cwd: dir,
    env: process.env,
  });
  if (!genKey.success) {
    throw new Error(`Failed to generate RSA key: ${genKey.output}`);
  }

  // Generate CSR
  const genCsr = await spawnAsync('openssl', [
    'req', '-new', '-key', privateKeyPath, '-out', csrPath,
    '-subj', '"/CN=Expoship Distribution Cert/O=Expoship/C=US"'
  ], {
    cwd: dir,
    env: process.env,
  });
  if (!genCsr.success) {
    throw new Error(`Failed to generate CSR: ${genCsr.output}`);
  }

  return { privateKeyPath: rawPrivateKeyPath, csrPath: rawCsrPath };
}

async function listIosDistributionCertificates(auth: Record<string, string>): Promise<any[]> {
  const url = 'https://api.appstoreconnect.apple.com/v1/certificates?limit=200';
  const res = await fetch(url, { headers: auth });
  if (!res.ok) {
    throw new Error(`List certificates HTTP ${res.status}: ${(await res.text()).slice(0, 400)}`);
  }
  const data: any = await res.json();
  const certs = data?.data || [];
  return certs.filter((c: any) => 
    c.attributes?.certificateType === 'IOS_DISTRIBUTION' || 
    c.attributes?.certificateType === 'DISTRIBUTION'
  );
}

async function revokeCertificate(auth: Record<string, string>, certId: string): Promise<void> {
  const url = `https://api.appstoreconnect.apple.com/v1/certificates/${certId}`;
  const res = await fetch(url, { method: 'DELETE', headers: auth });
  if (!res.ok) {
    throw new Error(`Delete certificate HTTP ${res.status}: ${(await res.text()).slice(0, 400)}`);
  }
}

async function ensureDistributionCertificate(
  auth: Record<string, string>,
  csrContent: string,
  dir: string,
  privateKeyPath: string
): Promise<{ certId: string; p12Path: string }> {
  const createCert = async () => {
    const url = 'https://api.appstoreconnect.apple.com/v1/certificates';
    const res = await fetch(url, {
      method: 'POST',
      headers: { ...auth, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        data: {
          type: 'certificates',
          attributes: {
            certificateType: 'IOS_DISTRIBUTION',
            csrContent: csrContent,
          },
        },
      }),
    });
    if (!res.ok) {
      const text = await res.text();
      return { success: false, status: res.status, error: text };
    }
    const data: any = await res.json();
    return { success: true, data };
  };

  let attempt = await createCert();
  if (!attempt.success) {
    const isLimit = /maximum number of certificates|exceeded.*limit|too many.*certificates|already have a current.*certificate/i.test(attempt.error || '');
    if (isLimit) {
      const certs = await listIosDistributionCertificates(auth);
      if (certs.length > 0) {
        certs.sort((a: any, b: any) => {
          const dateA = new Date(a.attributes?.expirationDate || 0).getTime();
          const dateB = new Date(b.attributes?.expirationDate || 0).getTime();
          return dateA - dateB;
        });
        const oldestCert = certs[0];
        console.log(`Revoking oldest certificate: ${oldestCert.id} (${oldestCert.attributes?.name})`);
        await revokeCertificate(auth, oldestCert.id);
        
        attempt = await createCert();
      }
    }
  }

  if (!attempt.success) {
    throw new Error(`App Store Connect certificate creation failed: ${attempt.error}`);
  }

  const certData = attempt.data?.data;
  const certId = certData?.id;
  const certificateContentB64 = certData?.attributes?.certificateContent;
  if (!certId || !certificateContentB64) {
    throw new Error(`Certificate creation response missing data: ${JSON.stringify(attempt.data)}`);
  }

  const rawCerPath = path.join(dir, `${certId}.cer`);
  const rawP12Path = path.join(dir, `${certId}.p12`);

  fs.writeFileSync(rawCerPath, Buffer.from(certificateContentB64, 'base64'));

  const p12Password = 'expoship';
  
  const bundleP12 = await spawnAsync('openssl', [
    'pkcs12', '-export',
    '-in', `"${rawCerPath}"`,
    '-inkey', `"${privateKeyPath}"`,
    '-out', `"${rawP12Path}"`,
    '-passout', `pass:${p12Password}`,
    '-name', '"Expoship Distribution Cert"',
    '-legacy',
    '-provider', 'default',
    '-provider', 'legacy'
  ], {
    cwd: dir,
    env: process.env,
  });

  if (!bundleP12.success) {
    throw new Error(`Failed to bundle .p12 using openssl: ${bundleP12.output}`);
  }

  try {
    fs.unlinkSync(rawCerPath);
  } catch (e) {}

  return { certId, p12Path: rawP12Path };
}

function detectRequiredCapabilities(projectRoot: string, appJson: any): string[] {
  const capabilities = new Set<string>();

  // 1. Check app.json entitlements
  const entitlements = appJson?.expo?.ios?.entitlements || {};
  if (entitlements['com.apple.developer.applesignin']) {
    capabilities.add('APPLE_ID_AUTH');
  }
  if (entitlements['aps-environment']) {
    capabilities.add('PUSH_NOTIFICATIONS');
  }
  if (entitlements['com.apple.developer.associated-domains']) {
    capabilities.add('ASSOCIATED_DOMAINS');
  }
  if (entitlements['com.apple.developer.icloud-container-identifiers'] || entitlements['com.apple.developer.icloud-services']) {
    capabilities.add('ICLOUD');
  }

  // 2. Check app.json plugins
  const plugins = appJson?.expo?.plugins || [];
  plugins.forEach((p: any) => {
    const pluginName = typeof p === 'string' ? p : (Array.isArray(p) ? p[0] : '');
    if (pluginName === 'expo-apple-authentication') {
      capabilities.add('APPLE_ID_AUTH');
    }
    if (pluginName === 'expo-notifications') {
      capabilities.add('PUSH_NOTIFICATIONS');
    }
  });

  // 3. Check package.json dependencies
  try {
    const pkgPath = path.join(projectRoot, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      if (deps['expo-apple-authentication'] || deps['@react-native-apple-authentication/ios']) {
        capabilities.add('APPLE_ID_AUTH');
      }
      if (deps['expo-notifications']) {
        capabilities.add('PUSH_NOTIFICATIONS');
      }
    }
  } catch (pkgErr) {
    console.error('Error scanning package.json dependencies for capabilities:', pkgErr);
  }

  // 4. Check any local .entitlements files
  try {
    const findEntitlementsFiles = (dir: string): string[] => {
      const results: string[] = [];
      if (!fs.existsSync(dir)) return results;
      const list = fs.readdirSync(dir);
      for (const file of list) {
        const filePath = path.join(dir, file);
        const stat = fs.statSync(filePath);
        if (stat && stat.isDirectory()) {
          if (file !== 'node_modules' && file !== '.git' && file !== '.expo' && file !== '.next') {
            results.push(...findEntitlementsFiles(filePath));
          }
        } else if (file.endsWith('.entitlements')) {
          results.push(filePath);
        }
      }
      return results;
    };

    const files = findEntitlementsFiles(projectRoot);
    for (const file of files) {
      const content = fs.readFileSync(file, 'utf8');
      if (content.includes('com.apple.developer.applesignin')) {
        capabilities.add('APPLE_ID_AUTH');
      }
      if (content.includes('aps-environment')) {
        capabilities.add('PUSH_NOTIFICATIONS');
      }
      if (content.includes('com.apple.developer.associated-domains')) {
        capabilities.add('ASSOCIATED_DOMAINS');
      }
      if (content.includes('com.apple.developer.icloud-container-identifiers') || content.includes('com.apple.developer.icloud-services')) {
        capabilities.add('ICLOUD');
      }
    }
  } catch (err) {
    console.error('Error scanning entitlements:', err);
  }

  return Array.from(capabilities);
}

async function enableBundleIdCapabilities(
  auth: Record<string, string>,
  bundleResourceId: string,
  capabilities: string[],
  appendLog?: (msg: string) => Promise<void>
): Promise<void> {
  for (const cap of capabilities) {
    try {
      const url = 'https://api.appstoreconnect.apple.com/v1/bundleIdCapabilities';
      const attributes: any = {
        capabilityType: cap
      };

      if (cap === 'APPLE_ID_AUTH') {
        attributes.settings = [
          {
            key: 'APPLE_ID_AUTH_APP_CONSENT',
            options: [
              {
                key: 'PRIMARY_APP_CONSENT'
              }
            ]
          }
        ];
      }

      const res = await fetch(url, {
        method: 'POST',
        headers: { ...auth, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          data: {
            type: 'bundleIdCapabilities',
            attributes,
            relationships: {
              bundleId: {
                data: {
                  type: 'bundleIds',
                  id: bundleResourceId
                }
              }
            }
          }
        }),
      });

      if (!res.ok) {
        const text = await res.text();
        const isAlreadyEnabled = text.includes('already exists') ||
                                 text.includes('already enabled') ||
                                 text.includes('ENTITY_EXISTS') ||
                                 text.includes('ENTITY_ERROR.ENTITY_EXISTS');

        if (isAlreadyEnabled) {
          if (appendLog) await appendLog(`[ASC CAPABILITY] Capability ${cap} is already enabled.`);
          console.log(`Capability ${cap} is already enabled.`);
        } else {
          if (appendLog) await appendLog(`[ASC CAPABILITY WARNING] Failed to enable capability ${cap} (HTTP ${res.status}): ${text}`);
          console.warn(`Warning: Failed to enable capability ${cap} (HTTP ${res.status}): ${text}`);
        }
      } else {
        if (appendLog) await appendLog(`[ASC CAPABILITY] Successfully enabled capability ${cap} for bundle ID.`);
        console.log(`Successfully enabled capability ${cap} for bundle ID.`);
      }
    } catch (err: any) {
      if (appendLog) await appendLog(`[ASC CAPABILITY WARNING] Failed to enable capability ${cap} due to error: ${err.message}`);
      console.warn(`Warning: Failed to enable capability ${cap} due to network error: ${err.message}`);
    }
  }
}

async function createProvisioningProfile(
  auth: Record<string, string>,
  bundleId: string,
  certId: string,
  dir: string,
  requiredCapabilities: string[] = [],
  appendLog?: (msg: string) => Promise<void>
): Promise<string> {
  const searchUrl = `https://api.appstoreconnect.apple.com/v1/bundleIds?filter[identifier]=${encodeURIComponent(bundleId)}`;
  const searchRes = await fetch(searchUrl, { headers: auth });
  if (!searchRes.ok) {
    throw new Error(`bundleIds search HTTP ${searchRes.status}: ${(await searchRes.text()).slice(0, 400)}`);
  }
  const searchData: any = await searchRes.json();
  let bundleResourceId: string | undefined = (searchData?.data || [])
    .find((b: any) => b?.attributes?.identifier === bundleId)?.id;

  if (!bundleResourceId) {
    const createRes = await fetch('https://api.appstoreconnect.apple.com/v1/bundleIds', {
      method: 'POST',
      headers: { ...auth, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        data: {
          type: 'bundleIds',
          attributes: { identifier: bundleId, name: bundleId.split('.').pop() || 'App', platform: 'IOS' },
        },
      }),
    });
    if (!createRes.ok) {
      throw new Error(`bundleIds POST HTTP ${createRes.status}: ${(await createRes.text()).slice(0, 400)}`);
    }
    const createData: any = await createRes.json();
    bundleResourceId = createData?.data?.id;
  }
  if (!bundleResourceId) {
    throw new Error(`Could not resolve bundleResourceId for ${bundleId}`);
  }

  // Enable required capabilities
  if (requiredCapabilities.length > 0) {
    await enableBundleIdCapabilities(auth, bundleResourceId, requiredCapabilities, appendLog);
    if (appendLog) await appendLog('Waiting 20 seconds for Apple capability changes to propagate across their servers...');
    await new Promise(resolve => setTimeout(resolve, 20000));
  }

  const listUrl = `https://api.appstoreconnect.apple.com/v1/profiles?filter[profileType]=IOS_APP_STORE&include=bundleId&limit=200`;
  const listRes = await fetch(listUrl, { headers: auth });
  if (listRes.ok) {
    const listData: any = await listRes.json();
    for (const prof of listData?.data || []) {
      const profBundleRel = prof?.relationships?.bundleId?.data?.id;
      if (profBundleRel !== bundleResourceId) continue;
      console.log(`Deleting existing profile: ${prof.id} (${prof?.attributes?.name})`);
      await fetch(`https://api.appstoreconnect.apple.com/v1/profiles/${prof.id}`, { method: 'DELETE', headers: auth });
    }
  }

  const profileName = `Expoship AppStore ${bundleId} ${Math.floor(Date.now() / 1000)}`;
  const createProfileRes = await fetch('https://api.appstoreconnect.apple.com/v1/profiles', {
    method: 'POST',
    headers: { ...auth, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: {
        type: 'profiles',
        attributes: { name: profileName, profileType: 'IOS_APP_STORE' },
        relationships: {
          bundleId: { data: { type: 'bundleIds', id: bundleResourceId } },
          certificates: { data: [{ type: 'certificates', id: certId }] },
        },
      },
    }),
  });

  if (!createProfileRes.ok) {
    throw new Error(`profiles POST HTTP ${createProfileRes.status}: ${(await createProfileRes.text()).slice(0, 800)}`);
  }

  const createProfileData: any = await createProfileRes.json();
  const profileContentB64 = createProfileData?.data?.attributes?.profileContent;
  if (!profileContentB64) {
    throw new Error(`Profile creation response missing content: ${JSON.stringify(createProfileData)}`);
  }

  const profilePath = path.join(dir, `${bundleId}.mobileprovision`);
  fs.writeFileSync(profilePath, Buffer.from(profileContentB64, 'base64'));

  return profilePath;
}

async function triggerEasBuildWithRetry(
  projectRoot: string,
  env: Record<string, string | undefined>,
  buildId: string,
  appendLog: (msg: string) => Promise<void>,
  attemptNum: number = 1
): Promise<void> {
  const maxAttempts = 3;
  await appendLog(`Triggering EAS production build for iOS (Attempt ${attemptNum}/${maxAttempts})...`);

  let buildOutput = '';
  const buildUrlRegex = /(https:\/\/expo\.dev\/accounts\/[\w-]+\/projects\/[\w-]+\/builds\/[\w-]+)/;

  const success = await new Promise<boolean>((resolve) => {
    const buildProcess = spawn(
      'npx',
      ['eas-cli', 'build', '--platform', 'ios', '--profile', 'production', '--non-interactive', '--no-wait'],
      {
        cwd: projectRoot,
        env,
        shell: true,
      }
    );

    buildProcess.stdout.on('data', async (data) => {
      const text = data.toString();
      buildOutput += text;
      const lines = text.split('\n');

      for (const line of lines) {
        if (!line.trim()) continue;
        await appendLog(`[EAS BUILD] ${line}`);

        const match = line.match(buildUrlRegex);
        if (match) {
          const buildUrl = match[1];
          await appendLog(`Detected Build URL: ${buildUrl}`);
          await Build.findByIdAndUpdate(buildId, { buildUrl });
        }
      }
    });

    buildProcess.stderr.on('data', async (data) => {
      const text = data.toString();
      buildOutput += text;
      const lines = text.split('\n');
      for (const line of lines) {
        if (line.trim()) {
          await appendLog(`[EAS BUILD ERROR] ${line}`);
        }
      }
    });

    buildProcess.on('close', (code) => {
      resolve(code === 0);
    });

    // 5 minutes safety timeout
    setTimeout(() => {
      buildProcess.kill();
      resolve(false);
    }, 300000);
  });

  if (success) {
    await appendLog('EAS build command completed successfully.');
    return;
  }

  // If failed, check for transient network errors to retry
  const transientErrors = [
    'ECONNRESET',
    'ETIMEDOUT',
    'Failed to upload',
    'upload failed',
    'socket hang up',
    'fetch failed',
    'network error'
  ];

  const isTransient = transientErrors.some(err => buildOutput.includes(err));

  if (isTransient && attemptNum < maxAttempts) {
    await appendLog(`Transient network error detected. Retrying in 5 seconds...`);
    await new Promise(r => setTimeout(r, 5000));
    return triggerEasBuildWithRetry(projectRoot, env, buildId, appendLog, attemptNum + 1);
  }

  throw new Error(`EAS build command failed with exit code 1. ${isTransient ? 'Max upload retries exceeded.' : ''}`);
}

// ─── Main Build Pipeline ────────────────────────────────────────────────────

export async function runBuild(
  buildId: string,
  zipFilePath: string,
  expoToken: string,
  p8KeyContent: string,
  issuerId: string,
  keyId: string,
  appleTeamId: string,
  customBundleId?: string,
  appleTeamType: string = 'COMPANY_OR_ORGANIZATION'
) {
  const tempDir = path.join(__dirname, '../../temp', buildId);

  const appendLog = async (message: string) => {
    console.log(`[Build ${buildId}]: ${message}`);
    await Build.findByIdAndUpdate(buildId, {
      $push: { logs: message }
    });
  };

  try {
    await Build.findByIdAndUpdate(buildId, { status: 'running' });
    await appendLog('Initializing build environment...');

    // ── Step 1: Extract ZIP ──────────────────────────────────────────────
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }

    await appendLog('Extracting project files...');
    const zip = new AdmZip(zipFilePath);
    zip.extractAllTo(tempDir, true);

    const projectRoot = findProjectRoot(tempDir);
    await appendLog(`Project root found at: ${projectRoot}`);

    // ── Step 2: Validate Expo token ──────────────────────────────────────
    await appendLog('Validating Expo access token...');
    const tokenCheck = await validateExpoToken(expoToken);
    if (!tokenCheck.valid) {
      throw new Error(`Expo token invalid: ${tokenCheck.error}. Generate a new one at expo.dev/settings/access-tokens`);
    }
    const expoUsername = tokenCheck.username!;
    await appendLog(`✓ Expo token valid — logged in as @${expoUsername}`);

    // ── Step 3: Read and configure app.json ──────────────────────────────
    const appJsonPath = path.join(projectRoot, 'app.json');
    if (!fs.existsSync(appJsonPath)) {
      throw new Error('No app.json found at project root. Expo projects require an app.json config.');
    }

    let appJson: any;
    try {
      appJson = JSON.parse(fs.readFileSync(appJsonPath, 'utf8'));
    } catch (err) {
      throw new Error(`Failed to parse app.json: ${(err as Error).message}`);
    }

    if (!appJson.expo) {
      appJson.expo = {};
    }

    // Set fallback name and slug if missing
    const projectName = appJson.expo.name || 'Expo Project';
    const slug = appJson.expo.slug || 'expo-project';
    appJson.expo.name = projectName;
    appJson.expo.slug = slug;

    // Inject owner so EAS knows which account to link to
    appJson.expo.owner = expoUsername;

    // Apply custom bundle identifier if provided, or read existing
    let bundleIdentifier = customBundleId || appJson.expo.ios?.bundleIdentifier;
    if (!bundleIdentifier) {
      bundleIdentifier = `com.anonymous.${slug.replace(/[^a-zA-Z0-9]/g, '')}`;
      await appendLog(`No bundle identifier found. Generating placeholder: ${bundleIdentifier}`);
    }

    if (!appJson.expo.ios) {
      appJson.expo.ios = {};
    }
    appJson.expo.ios.bundleIdentifier = bundleIdentifier;

    // Add App Store encryption compliance flag to avoid manual ASC configuration
    if (!appJson.expo.ios.infoPlist) {
      appJson.expo.ios.infoPlist = {};
    }
    appJson.expo.ios.infoPlist.ITSAppUsesNonExemptEncryption = false;

    // Write back app.json
    fs.writeFileSync(appJsonPath, JSON.stringify(appJson, null, 2));
    await appendLog(`Configured app.json: name="${projectName}", slug="${slug}", owner="${expoUsername}", bundleIdentifier="${bundleIdentifier}"`);

    // Update build model with parsed metadata
    await Build.findByIdAndUpdate(buildId, {
      projectName,
      slug,
      bundleIdentifier
    });

    // ── Step 4: Write .p8 key and provision iOS Credentials Locally ──────
    const credentialsDir = path.join(projectRoot, 'credentials');
    if (!fs.existsSync(credentialsDir)) {
      fs.mkdirSync(credentialsDir, { recursive: true });
    }
    const p8Path = path.resolve(credentialsDir, 'asc_key.p8');
    // Sanitize line endings for the key
    fs.writeFileSync(p8Path, p8KeyContent.replace(/\r/g, ''));
    await appendLog('Apple Developer Admin Key (.p8) written to workspace.');

    await appendLog('Provisioning iOS distribution certificate and provisioning profile locally...');
    
    // Sign JWT
    const jwtToken = signAscJwt({ p8Content: p8KeyContent, keyId, issuerId });
    const ascAuth = { Authorization: `Bearer ${jwtToken}` };

    // Create temp keys and CSR
    const { privateKeyPath, csrPath } = await generateKeyAndCsr(credentialsDir);
    const csrContent = fs.readFileSync(csrPath, 'utf8');

    // Create distribution certificate
    const { certId, p12Path } = await ensureDistributionCertificate(
      ascAuth,
      csrContent,
      credentialsDir,
      privateKeyPath
    );
    await appendLog(`✓ Provisioned iOS distribution certificate (ID: ${certId})`);

    // Detect required capabilities
    const requiredCaps = detectRequiredCapabilities(projectRoot, appJson);
    if (requiredCaps.length > 0) {
      await appendLog(`Detected required iOS capabilities from entitlements: ${requiredCaps.join(', ')}`);
    }

    // Create provisioning profile
    const profilePath = await createProvisioningProfile(
      ascAuth,
      bundleIdentifier,
      certId,
      credentialsDir,
      requiredCaps,
      appendLog
    );
    await appendLog(`✓ Provisioned iOS App Store provisioning profile for bundle ID "${bundleIdentifier}"`);

    // Cleanup temp CSR and private key
    try {
      fs.unlinkSync(privateKeyPath);
      fs.unlinkSync(csrPath);
    } catch (e) {}

    // Write credentials.json
    const targetName = projectName.replace(/[\W_]+/g, '').normalize('NFD').replace(/[̀-ͯ]/g, '') || 'app';
    const credentialsJsonPath = path.join(projectRoot, 'credentials.json');
    const credentialsJson = {
      ios: {
        [targetName]: {
          provisioningProfilePath: path.relative(projectRoot, profilePath),
          distributionCertificate: {
            path: path.relative(projectRoot, p12Path),
            password: 'expoship'
          }
        }
      }
    };
    fs.writeFileSync(credentialsJsonPath, JSON.stringify(credentialsJson, null, 2));
    await appendLog(`Wrote credentials.json for target "${targetName}".`);

    // ── Step 5: Configure eas.json ───────────────────────────────────────
    const easJsonPath = path.join(projectRoot, 'eas.json');
    const easJson: any = {
      cli: {
        version: ">= 3.0.0",
        appVersionSource: "remote"
      },
      build: {
        development: {
          developmentClient: true,
          distribution: "internal"
        },
        preview: {
          distribution: "internal"
        },
        production: {
          credentialsSource: "local",
          distribution: "store",
          autoIncrement: true
        }
      }
    };

    // If there's an existing eas.json, try to merge in the build.production
    if (fs.existsSync(easJsonPath)) {
      try {
        const existing = JSON.parse(fs.readFileSync(easJsonPath, 'utf8'));
        // Preserve existing production config but don't let invalid fields break init
        if (existing.build?.production) {
          // Remove any fields that cause eas init validation errors
          const { ascApiKeyPath, ascApiKeyId, ascApiKeyIssuerId, ...cleanProd } = existing.build.production;
          const { ascApiKeyPath: _a, ascApiKeyId: _b, ascApiKeyIssuerId: _c, ...cleanIos } = (existing.build?.production?.ios || {});
          easJson.build.production = {
            ...cleanProd,
            credentialsSource: "local",
            distribution: "store",
            autoIncrement: true
          };
          if (Object.keys(cleanIos).length > 0) {
            easJson.build.production.ios = cleanIos;
          }
        }
      } catch (e) {
        await appendLog('Warning: Could not parse existing eas.json. Using clean defaults.');
      }
    }

    fs.writeFileSync(easJsonPath, JSON.stringify(easJson, null, 2));
    await appendLog('Ensured valid eas.json configuration file is present with credentialsSource="local".');

    // ── Step 6: Build environment variables ──────────────────────────────
    // All Apple credentials are passed via env vars — EAS CLI reads them
    // automatically in --non-interactive mode.
    const env: Record<string, string | undefined> = {
      ...process.env,
      EXPO_TOKEN: expoToken,
      // Apple credential env vars (EAS CLI reads these automatically)
      EXPO_ASC_API_KEY_PATH: p8Path,
      EXPO_ASC_KEY_ID: keyId,
      EXPO_ASC_ISSUER_ID: issuerId,
      EXPO_APPLE_TEAM_ID: appleTeamId,
      EXPO_APPLE_TEAM_TYPE: appleTeamType,
      // CI/CD flags
      CI: '1',
      EAS_NO_VCS: '1',
      EAS_PROJECT_ROOT: projectRoot,
      EAS_BUILD_NO_EXPO_GO_WARNING: 'true',
    };

    // ── Step 6b: Install dependencies and sync lockfile ──
    const hasPackageJson = fs.existsSync(path.join(projectRoot, 'package.json'));

    if (hasPackageJson) {
      const hasYarnLock = fs.existsSync(path.join(projectRoot, 'yarn.lock'));
      const hasPnpmLock = fs.existsSync(path.join(projectRoot, 'pnpm-lock.yaml'));
      
      let pm = 'npm';
      let installCmd = 'npm';
      let installArgs = ['install', '--legacy-peer-deps'];
      let logPrefix = 'NPM';

      if (hasYarnLock) {
        pm = 'yarn';
        installCmd = 'yarn';
        installArgs = ['install', '--non-interactive'];
        logPrefix = 'YARN';
      } else if (hasPnpmLock) {
        pm = 'pnpm';
        installCmd = 'pnpm';
        installArgs = ['install'];
        logPrefix = 'PNPM';
      } else {
        // For npm, inject legacy-peer-deps to .npmrc to prevent EAS build peer dependency failures
        try {
          const npmrcPath = path.join(projectRoot, '.npmrc');
          let npmrcContent = '';
          if (fs.existsSync(npmrcPath)) {
            npmrcContent = fs.readFileSync(npmrcPath, 'utf8');
          }
          if (!npmrcContent.includes('legacy-peer-deps')) {
            fs.writeFileSync(npmrcPath, npmrcContent + '\nlegacy-peer-deps=true\n');
            await appendLog('Added legacy-peer-deps=true to .npmrc to prevent EAS build peer dependency failures.');
          }
        } catch (npmrcErr: any) {
          await appendLog(`Warning: Failed to configure .npmrc: ${npmrcErr.message}`);
        }
      }

      await appendLog(`Installing project dependencies and syncing lockfile (${pm} install)...`);
      const installResult = await spawnAsync(
        installCmd,
        installArgs,
        { cwd: projectRoot, env, timeoutMs: 600000 },
        (data) => {
          const lines = data.split('\n');
          lines.forEach((line: string) => {
            if (line.trim()) appendLog(`[${logPrefix}] ${line.trim()}`);
          });
        }
      );

      if (!installResult.success) {
        throw new Error(`Project dependency installation failed (${pm} install exited with non-zero code or timed out). Output: ${installResult.output.substring(0, 1000)}`);
      } else {
        await appendLog('Dependencies and lockfile synced successfully.');
      }
    } else {
      await appendLog('Warning: No package.json found. Skipping dependency installation.');
    }

    // ── Step 7: Link project to Expo account (eas init) ──────────────────
    const hasProjectId = appJson.expo?.extra?.eas?.projectId;
    if (!hasProjectId) {
      await appendLog('EAS Project ID is missing. Linking project with Expo CLI...');

      const initResult = await spawnAsync(
        'npx',
        ['eas-cli', 'init', '--non-interactive', '--force'],
        { cwd: projectRoot, env, timeoutMs: 60000 },
        (data) => {
          const lines = data.split('\n');
          lines.forEach((line: string) => {
            if (line.trim()) appendLog(`[EAS INIT] ${line.trim()}`);
          });
        }
      );

      if (!initResult.success) {
        // Check if it actually linked despite non-zero exit
        const updatedAppJson = JSON.parse(fs.readFileSync(appJsonPath, 'utf8'));
        const linkedId = updatedAppJson?.expo?.extra?.eas?.projectId;
        if (linkedId) {
          await appendLog(`EAS project linked despite CLI warning (ID: ${linkedId}).`);
        } else {
          throw new Error(`EAS project init failed. Output: ${initResult.output.substring(0, 500)}`);
        }
      } else {
        await appendLog('EAS project initialization successful.');
      }
    } else {
      await appendLog(`EAS Project ID already exists in app.json: ${hasProjectId}`);
    }

    // ── Step 8: Trigger production iOS build ─────────────────────────────
    await appendLog('Apple credentials configured via environment variables (ASC API Key, Team ID, Team Type).');
    await appendLog('Triggering EAS production build for iOS. Uploading assets to Expo Cloud...');

    await triggerEasBuildWithRetry(projectRoot, env, buildId, appendLog);

    // Fetch the updated build document to check if we captured the build URL
    const finalBuild = await Build.findById(buildId);
    await Build.findByIdAndUpdate(buildId, { status: 'completed' });
    await appendLog(`Build triggered successfully! Access it here: ${finalBuild?.buildUrl || 'Check your Expo account dashboard'}`);

  } catch (error) {
    const errMsg = (error as Error).message;
    await appendLog(`Build process failed: ${errMsg}`);
    await Build.findByIdAndUpdate(buildId, { status: 'failed' });
  } finally {
    // ── Cleanup temp folder and uploaded ZIP ─────────────────────────────
    try {
      if (fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true, force: true });
        await appendLog('Cleaned up temporary workspace.');
      }
      if (fs.existsSync(zipFilePath)) {
        fs.unlinkSync(zipFilePath);
      }
    } catch (cleanupErr) {
      console.error('Failed to clean up temporary workspace files:', cleanupErr);
    }
  }
}

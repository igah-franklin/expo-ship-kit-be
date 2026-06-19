"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runBuild = runBuild;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const child_process_1 = require("child_process");
const adm_zip_1 = __importDefault(require("adm-zip"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const Build_1 = __importDefault(require("../models/Build"));
// ─── Helpers ────────────────────────────────────────────────────────────────
/** Recursively find the directory containing app.json / app.config.js */
function findProjectRoot(dir) {
    if (fs_1.default.existsSync(path_1.default.join(dir, 'app.json')) ||
        fs_1.default.existsSync(path_1.default.join(dir, 'app.config.js')) ||
        fs_1.default.existsSync(path_1.default.join(dir, 'app.config.ts'))) {
        return dir;
    }
    const files = fs_1.default.readdirSync(dir);
    for (const file of files) {
        const fullPath = path_1.default.join(dir, file);
        if (fs_1.default.statSync(fullPath).isDirectory()) {
            if (file === 'node_modules' || file === '.git' || file === '.expo') {
                continue;
            }
            const found = findProjectRoot(fullPath);
            if (found)
                return found;
        }
    }
    return dir;
}
/** Spawn a process and collect output, with optional timeout */
function spawnAsync(cmd, args, opts, onData) {
    return new Promise((resolve) => {
        const proc = (0, child_process_1.spawn)(cmd, args, {
            cwd: opts.cwd,
            env: opts.env,
            shell: true,
            stdio: ['pipe', 'pipe', 'pipe'],
        });
        let output = '';
        proc.stdout?.on('data', (d) => {
            const s = d.toString();
            output += s;
            onData?.(s);
        });
        proc.stderr?.on('data', (d) => {
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
async function validateExpoToken(token) {
    try {
        const res = await fetch('https://api.expo.dev/graphql', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({ query: '{ me { username } }' }),
        });
        const data = await res.json();
        if (data?.errors?.length) {
            return { valid: false, error: data.errors[0]?.message || 'Invalid token' };
        }
        const username = data?.data?.me?.username;
        if (!username)
            return { valid: false, error: 'Could not fetch Expo account — token may be invalid' };
        return { valid: true, username };
    }
    catch (err) {
        return { valid: false, error: `Network error reaching Expo: ${err.message}` };
    }
}
// ─── Apple Local Provisioning Helpers ────────────────────────────────────────
/** Sign an App Store Connect JWT with the user-uploaded .p8 */
function signAscJwt(ascApiKey) {
    const now = Math.floor(Date.now() / 1000);
    return jsonwebtoken_1.default.sign({ iss: ascApiKey.issuerId, iat: now, exp: now + 20 * 60, aud: 'appstoreconnect-v1' }, ascApiKey.p8Content, { algorithm: 'ES256', header: { alg: 'ES256', kid: ascApiKey.keyId, typ: 'JWT' } });
}
/** Generate private key and CSR locally using openssl */
async function generateKeyAndCsr(dir) {
    const rawPrivateKeyPath = path_1.default.join(dir, 'temp_private.key');
    const rawCsrPath = path_1.default.join(dir, 'temp_request.csr');
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
        '-subj', '"/CN=Hangar Distribution Cert/O=Hangar/C=US"'
    ], {
        cwd: dir,
        env: process.env,
    });
    if (!genCsr.success) {
        throw new Error(`Failed to generate CSR: ${genCsr.output}`);
    }
    return { privateKeyPath: rawPrivateKeyPath, csrPath: rawCsrPath };
}
async function listIosDistributionCertificates(auth) {
    const url = 'https://api.appstoreconnect.apple.com/v1/certificates?filter[certificateType]=IOS_DISTRIBUTION&limit=200';
    const res = await fetch(url, { headers: auth });
    if (!res.ok) {
        throw new Error(`List certificates HTTP ${res.status}: ${(await res.text()).slice(0, 400)}`);
    }
    const data = await res.json();
    return data?.data || [];
}
async function revokeCertificate(auth, certId) {
    const url = `https://api.appstoreconnect.apple.com/v1/certificates/${certId}`;
    const res = await fetch(url, { method: 'DELETE', headers: auth });
    if (!res.ok) {
        throw new Error(`Delete certificate HTTP ${res.status}: ${(await res.text()).slice(0, 400)}`);
    }
}
async function ensureDistributionCertificate(auth, csrContent, dir, privateKeyPath) {
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
        const data = await res.json();
        return { success: true, data };
    };
    let attempt = await createCert();
    if (!attempt.success) {
        const isLimit = /maximum number of certificates|exceeded.*limit|too many.*certificates/i.test(attempt.error || '');
        if (isLimit) {
            const certs = await listIosDistributionCertificates(auth);
            if (certs.length > 0) {
                certs.sort((a, b) => {
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
    const rawCerPath = path_1.default.join(dir, `${certId}.cer`);
    const rawP12Path = path_1.default.join(dir, `${certId}.p12`);
    fs_1.default.writeFileSync(rawCerPath, Buffer.from(certificateContentB64, 'base64'));
    const p12Password = 'hangar';
    const bundleP12 = await spawnAsync('openssl', [
        'pkcs12', '-export',
        '-in', `"${rawCerPath}"`,
        '-inkey', `"${privateKeyPath}"`,
        '-out', `"${rawP12Path}"`,
        '-passout', `pass:${p12Password}`,
        '-name', '"Hangar Distribution Cert"'
    ], {
        cwd: dir,
        env: process.env,
    });
    if (!bundleP12.success) {
        throw new Error(`Failed to bundle .p12 using openssl: ${bundleP12.output}`);
    }
    try {
        fs_1.default.unlinkSync(rawCerPath);
    }
    catch (e) { }
    return { certId, p12Path: rawP12Path };
}
async function createProvisioningProfile(auth, bundleId, certId, dir) {
    const searchUrl = `https://api.appstoreconnect.apple.com/v1/bundleIds?filter[identifier]=${encodeURIComponent(bundleId)}`;
    const searchRes = await fetch(searchUrl, { headers: auth });
    if (!searchRes.ok) {
        throw new Error(`bundleIds search HTTP ${searchRes.status}: ${(await searchRes.text()).slice(0, 400)}`);
    }
    const searchData = await searchRes.json();
    let bundleResourceId = (searchData?.data || [])
        .find((b) => b?.attributes?.identifier === bundleId)?.id;
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
        const createData = await createRes.json();
        bundleResourceId = createData?.data?.id;
    }
    if (!bundleResourceId) {
        throw new Error(`Could not resolve bundleResourceId for ${bundleId}`);
    }
    const listUrl = `https://api.appstoreconnect.apple.com/v1/profiles?filter[profileType]=IOS_APP_STORE&include=bundleId&limit=200`;
    const listRes = await fetch(listUrl, { headers: auth });
    if (listRes.ok) {
        const listData = await listRes.json();
        for (const prof of listData?.data || []) {
            const profBundleRel = prof?.relationships?.bundleId?.data?.id;
            if (profBundleRel !== bundleResourceId)
                continue;
            console.log(`Deleting existing profile: ${prof.id} (${prof?.attributes?.name})`);
            await fetch(`https://api.appstoreconnect.apple.com/v1/profiles/${prof.id}`, { method: 'DELETE', headers: auth });
        }
    }
    const profileName = `Hangar AppStore ${bundleId} ${Math.floor(Date.now() / 1000)}`;
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
    const createProfileData = await createProfileRes.json();
    const profileContentB64 = createProfileData?.data?.attributes?.profileContent;
    if (!profileContentB64) {
        throw new Error(`Profile creation response missing content: ${JSON.stringify(createProfileData)}`);
    }
    const profilePath = path_1.default.join(dir, `${bundleId}.mobileprovision`);
    fs_1.default.writeFileSync(profilePath, Buffer.from(profileContentB64, 'base64'));
    return profilePath;
}
// ─── Main Build Pipeline ────────────────────────────────────────────────────
async function runBuild(buildId, zipFilePath, expoToken, p8KeyContent, issuerId, keyId, appleTeamId, customBundleId, appleTeamType = 'COMPANY_OR_ORGANIZATION') {
    const tempDir = path_1.default.join(__dirname, '../../temp', buildId);
    const appendLog = async (message) => {
        console.log(`[Build ${buildId}]: ${message}`);
        await Build_1.default.findByIdAndUpdate(buildId, {
            $push: { logs: message }
        });
    };
    try {
        await Build_1.default.findByIdAndUpdate(buildId, { status: 'running' });
        await appendLog('Initializing build environment...');
        // ── Step 1: Extract ZIP ──────────────────────────────────────────────
        if (!fs_1.default.existsSync(tempDir)) {
            fs_1.default.mkdirSync(tempDir, { recursive: true });
        }
        await appendLog('Extracting project files...');
        const zip = new adm_zip_1.default(zipFilePath);
        zip.extractAllTo(tempDir, true);
        const projectRoot = findProjectRoot(tempDir);
        await appendLog(`Project root found at: ${projectRoot}`);
        // ── Step 2: Validate Expo token ──────────────────────────────────────
        await appendLog('Validating Expo access token...');
        const tokenCheck = await validateExpoToken(expoToken);
        if (!tokenCheck.valid) {
            throw new Error(`Expo token invalid: ${tokenCheck.error}. Generate a new one at expo.dev/settings/access-tokens`);
        }
        const expoUsername = tokenCheck.username;
        await appendLog(`✓ Expo token valid — logged in as @${expoUsername}`);
        // ── Step 3: Read and configure app.json ──────────────────────────────
        const appJsonPath = path_1.default.join(projectRoot, 'app.json');
        if (!fs_1.default.existsSync(appJsonPath)) {
            throw new Error('No app.json found at project root. Expo projects require an app.json config.');
        }
        let appJson;
        try {
            appJson = JSON.parse(fs_1.default.readFileSync(appJsonPath, 'utf8'));
        }
        catch (err) {
            throw new Error(`Failed to parse app.json: ${err.message}`);
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
        fs_1.default.writeFileSync(appJsonPath, JSON.stringify(appJson, null, 2));
        await appendLog(`Configured app.json: name="${projectName}", slug="${slug}", owner="${expoUsername}", bundleIdentifier="${bundleIdentifier}"`);
        // Update build model with parsed metadata
        await Build_1.default.findByIdAndUpdate(buildId, {
            projectName,
            slug,
            bundleIdentifier
        });
        // ── Step 4: Write .p8 key and provision iOS Credentials Locally ──────
        const credentialsDir = path_1.default.join(projectRoot, 'credentials');
        if (!fs_1.default.existsSync(credentialsDir)) {
            fs_1.default.mkdirSync(credentialsDir, { recursive: true });
        }
        const p8Path = path_1.default.resolve(credentialsDir, 'asc_key.p8');
        // Sanitize line endings for the key
        fs_1.default.writeFileSync(p8Path, p8KeyContent.replace(/\r/g, ''));
        await appendLog('Apple Developer Admin Key (.p8) written to workspace.');
        await appendLog('Provisioning iOS distribution certificate and provisioning profile locally...');
        // Sign JWT
        const jwtToken = signAscJwt({ p8Content: p8KeyContent, keyId, issuerId });
        const ascAuth = { Authorization: `Bearer ${jwtToken}` };
        // Create temp keys and CSR
        const { privateKeyPath, csrPath } = await generateKeyAndCsr(credentialsDir);
        const csrContent = fs_1.default.readFileSync(csrPath, 'utf8');
        // Create distribution certificate
        const { certId, p12Path } = await ensureDistributionCertificate(ascAuth, csrContent, credentialsDir, privateKeyPath);
        await appendLog(`✓ Provisioned iOS distribution certificate (ID: ${certId})`);
        // Create provisioning profile
        const profilePath = await createProvisioningProfile(ascAuth, bundleIdentifier, certId, credentialsDir);
        await appendLog(`✓ Provisioned iOS App Store provisioning profile for bundle ID "${bundleIdentifier}"`);
        // Cleanup temp CSR and private key
        try {
            fs_1.default.unlinkSync(privateKeyPath);
            fs_1.default.unlinkSync(csrPath);
        }
        catch (e) { }
        // Write credentials.json
        const targetName = projectName.replace(/[\W_]+/g, '').normalize('NFD').replace(/[̀-ͯ]/g, '') || 'app';
        const credentialsJsonPath = path_1.default.join(projectRoot, 'credentials.json');
        const credentialsJson = {
            ios: {
                [targetName]: {
                    provisioningProfilePath: path_1.default.relative(projectRoot, profilePath),
                    distributionCertificate: {
                        path: path_1.default.relative(projectRoot, p12Path),
                        password: 'hangar'
                    }
                }
            }
        };
        fs_1.default.writeFileSync(credentialsJsonPath, JSON.stringify(credentialsJson, null, 2));
        await appendLog(`Wrote credentials.json for target "${targetName}".`);
        // ── Step 5: Configure eas.json ───────────────────────────────────────
        const easJsonPath = path_1.default.join(projectRoot, 'eas.json');
        const easJson = {
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
        if (fs_1.default.existsSync(easJsonPath)) {
            try {
                const existing = JSON.parse(fs_1.default.readFileSync(easJsonPath, 'utf8'));
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
            }
            catch (e) {
                await appendLog('Warning: Could not parse existing eas.json. Using clean defaults.');
            }
        }
        fs_1.default.writeFileSync(easJsonPath, JSON.stringify(easJson, null, 2));
        await appendLog('Ensured valid eas.json configuration file is present with credentialsSource="local".');
        // ── Step 6: Build environment variables ──────────────────────────────
        // All Apple credentials are passed via env vars — EAS CLI reads them
        // automatically in --non-interactive mode.
        const env = {
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
        // ── Step 6b: Install dependencies (uploaded ZIPs lack node_modules) ──
        const hasNodeModules = fs_1.default.existsSync(path_1.default.join(projectRoot, 'node_modules'));
        const hasPackageJson = fs_1.default.existsSync(path_1.default.join(projectRoot, 'package.json'));
        if (!hasNodeModules && hasPackageJson) {
            await appendLog('Installing project dependencies (npm install)...');
            const installResult = await spawnAsync('npm', ['install', '--legacy-peer-deps'], { cwd: projectRoot, env, timeoutMs: 180000 }, (data) => {
                const lines = data.split('\n');
                lines.forEach((line) => {
                    if (line.trim())
                        appendLog(`[NPM] ${line.trim()}`);
                });
            });
            if (!installResult.success) {
                await appendLog('Warning: npm install had issues, attempting to continue...');
                await appendLog(`[NPM OUTPUT] ${installResult.output.substring(0, 500)}`);
            }
            else {
                await appendLog('Dependencies installed successfully.');
            }
        }
        else if (hasNodeModules) {
            await appendLog('node_modules already present, skipping npm install.');
        }
        else {
            await appendLog('Warning: No package.json found. Skipping dependency installation.');
        }
        // ── Step 7: Link project to Expo account (eas init) ──────────────────
        const hasProjectId = appJson.expo?.extra?.eas?.projectId;
        if (!hasProjectId) {
            await appendLog('EAS Project ID is missing. Linking project with Expo CLI...');
            const initResult = await spawnAsync('npx', ['eas-cli', 'init', '--non-interactive', '--force'], { cwd: projectRoot, env, timeoutMs: 60000 }, (data) => {
                const lines = data.split('\n');
                lines.forEach((line) => {
                    if (line.trim())
                        appendLog(`[EAS INIT] ${line.trim()}`);
                });
            });
            if (!initResult.success) {
                // Check if it actually linked despite non-zero exit
                const updatedAppJson = JSON.parse(fs_1.default.readFileSync(appJsonPath, 'utf8'));
                const linkedId = updatedAppJson?.expo?.extra?.eas?.projectId;
                if (linkedId) {
                    await appendLog(`EAS project linked despite CLI warning (ID: ${linkedId}).`);
                }
                else {
                    throw new Error(`EAS project init failed. Output: ${initResult.output.substring(0, 500)}`);
                }
            }
            else {
                await appendLog('EAS project initialization successful.');
            }
        }
        else {
            await appendLog(`EAS Project ID already exists in app.json: ${hasProjectId}`);
        }
        // ── Step 8: Trigger production iOS build ─────────────────────────────
        await appendLog('Apple credentials configured via environment variables (ASC API Key, Team ID, Team Type).');
        await appendLog('Triggering EAS production build for iOS. Uploading assets to Expo Cloud...');
        await new Promise((resolve, reject) => {
            const buildProcess = (0, child_process_1.spawn)('npx', ['eas-cli', 'build', '--platform', 'ios', '--profile', 'production', '--non-interactive', '--no-wait'], {
                cwd: projectRoot,
                env,
                shell: true,
            });
            const buildUrlRegex = /(https:\/\/expo\.dev\/accounts\/[\w-]+\/projects\/[\w-]+\/builds\/[\w-]+)/;
            buildProcess.stdout.on('data', async (data) => {
                const text = data.toString();
                const lines = text.split('\n');
                for (const line of lines) {
                    if (!line.trim())
                        continue;
                    await appendLog(`[EAS BUILD] ${line}`);
                    // Look for Expo Build URL
                    const match = line.match(buildUrlRegex);
                    if (match) {
                        const buildUrl = match[1];
                        await appendLog(`Detected Build URL: ${buildUrl}`);
                        await Build_1.default.findByIdAndUpdate(buildId, { buildUrl });
                    }
                }
            });
            buildProcess.stderr.on('data', (data) => {
                const lines = data.toString().split('\n');
                lines.forEach((line) => {
                    if (line.trim())
                        appendLog(`[EAS BUILD ERROR] ${line}`);
                });
            });
            buildProcess.on('close', async (code) => {
                if (code === 0) {
                    await appendLog('EAS build command completed successfully.');
                    resolve();
                }
                else {
                    reject(new Error(`EAS build command failed with exit code ${code}`));
                }
            });
            // Safety timeout at 5 minutes
            setTimeout(() => {
                buildProcess.kill();
                reject(new Error('EAS build command timed out after 5 minutes'));
            }, 300000);
        });
        // Fetch the updated build document to check if we captured the build URL
        const finalBuild = await Build_1.default.findById(buildId);
        await Build_1.default.findByIdAndUpdate(buildId, { status: 'completed' });
        await appendLog(`Build triggered successfully! Access it here: ${finalBuild?.buildUrl || 'Check your Expo account dashboard'}`);
    }
    catch (error) {
        const errMsg = error.message;
        await appendLog(`Build process failed: ${errMsg}`);
        await Build_1.default.findByIdAndUpdate(buildId, { status: 'failed' });
    }
    finally {
        // ── Cleanup temp folder and uploaded ZIP ─────────────────────────────
        try {
            if (fs_1.default.existsSync(tempDir)) {
                fs_1.default.rmSync(tempDir, { recursive: true, force: true });
                await appendLog('Cleaned up temporary workspace.');
            }
            if (fs_1.default.existsSync(zipFilePath)) {
                fs_1.default.unlinkSync(zipFilePath);
            }
        }
        catch (cleanupErr) {
            console.error('Failed to clean up temporary workspace files:', cleanupErr);
        }
    }
}

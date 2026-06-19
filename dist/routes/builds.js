"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const multer_1 = __importDefault(require("multer"));
const fs_1 = __importDefault(require("fs"));
const Build_1 = __importDefault(require("../models/Build"));
const buildService_1 = require("../services/buildService");
const router = express_1.default.Router();
// Setup multer for uploading ZIP file and .p8 developer key
const upload = (0, multer_1.default)({ dest: 'uploads/' });
// Mask token for DB storage
function maskToken(token) {
    if (!token)
        return '';
    if (token.length <= 8)
        return '********';
    return `${token.substring(0, 4)}...${token.substring(token.length - 4)}`;
}
// 1. GET /api/builds - List build history
router.get('/', async (req, res) => {
    try {
        const builds = await Build_1.default.find().sort({ createdAt: -1 }).limit(50);
        return res.json({ success: true, builds });
    }
    catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});
// 2. GET /api/builds/:id - Get specific build status and logs
router.get('/:id', async (req, res) => {
    try {
        const build = await Build_1.default.findById(req.params.id);
        if (!build) {
            return res.status(404).json({ success: false, message: 'Build not found.' });
        }
        return res.json({ success: true, build });
    }
    catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});
// 3. POST /api/builds - Upload files and trigger new build
router.post('/', upload.fields([
    { name: 'project', maxCount: 1 },
    { name: 'appleKey', maxCount: 1 }
]), async (req, res) => {
    try {
        const files = req.files;
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
        const p8KeyContent = fs_1.default.readFileSync(appleKeyFile.path, 'utf8');
        // Clean up the temporary uploaded key file immediately from backend uploads directory
        try {
            fs_1.default.unlinkSync(appleKeyFile.path);
        }
        catch (err) {
            console.error('Failed to unlink temp uploaded key file:', err);
        }
        // Create initial build record in MongoDB
        const build = new Build_1.default({
            projectName: 'Preparing...',
            slug: 'preparing',
            bundleIdentifier: customBundleId || 'Checking...',
            status: 'pending',
            logs: ['Received upload. Initializing build pipeline...'],
            expoTokenMasked: maskToken(expoToken)
        });
        await build.save();
        // Trigger build service asynchronously
        (0, buildService_1.runBuild)(build._id.toString(), projectFile.path, expoToken, p8KeyContent, issuerId, keyId, appleTeamId, customBundleId, appleTeamType || 'COMPANY_OR_ORGANIZATION').catch((err) => {
            console.error(`Error in runBuild async promise for build ${build._id}:`, err);
        });
        return res.status(201).json({
            success: true,
            message: 'Build pipeline triggered successfully.',
            build
        });
    }
    catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});
exports.default = router;

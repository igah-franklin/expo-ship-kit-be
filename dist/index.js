"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const dotenv_1 = __importDefault(require("dotenv"));
const mongoose_1 = __importDefault(require("mongoose"));
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
const builds_1 = __importDefault(require("./routes/builds"));
// Load environment variables
dotenv_1.default.config();
const app = (0, express_1.default)();
const PORT = process.env.PORT || 5001;
// Middlewares
app.use((0, cors_1.default)());
app.use(express_1.default.json());
// Ensure temporary folders exist
const uploadsDir = path_1.default.join(__dirname, '../uploads');
const tempDir = path_1.default.join(__dirname, '../temp');
if (!fs_1.default.existsSync(uploadsDir)) {
    fs_1.default.mkdirSync(uploadsDir, { recursive: true });
}
if (!fs_1.default.existsSync(tempDir)) {
    fs_1.default.mkdirSync(tempDir, { recursive: true });
}
// Connect to MongoDB
const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/expo-ship-kit';
mongoose_1.default
    .connect(mongoUri)
    .then(() => console.log('Successfully connected to MongoDB database.'))
    .catch((err) => {
    console.error('Failed to connect to MongoDB:', err.message);
    process.exit(1);
});
// Base API Routes
app.use('/api/builds', builds_1.default);
// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ success: true, message: 'Server is healthy.' });
});
// Start listening
app.listen(PORT, () => {
    console.log(`Backend Express server is running on http://localhost:${PORT}`);
});

import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import path from 'path';
import fs from 'fs';
import buildsRouter from './routes/builds';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5001;

// Middlewares
app.use(cors());
app.use(express.json());

// Ensure temporary folders exist
const uploadsDir = path.join(__dirname, '../uploads');
const tempDir = path.join(__dirname, '../temp');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
if (!fs.existsSync(tempDir)) {
  fs.mkdirSync(tempDir, { recursive: true });
}

// Connect to MongoDB
const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/expo-ship-kit';
mongoose
  .connect(mongoUri)
  .then(() => console.log('Successfully connected to MongoDB database.'))
  .catch((err) => {
    console.error('Failed to connect to MongoDB:', err.message);
    process.exit(1);
  });

// Base API Routes
app.use('/api/builds', buildsRouter);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ success: true, message: 'Server is healthy.' });
});

// Start listening
app.listen(PORT, () => {
  console.log(`Backend Express server is running on http://localhost:${PORT}`);
});

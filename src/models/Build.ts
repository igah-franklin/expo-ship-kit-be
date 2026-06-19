import mongoose, { Schema, Document } from 'mongoose';

export interface IBuild extends Document {
  projectName: string;
  slug: string;
  bundleIdentifier: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  buildUrl?: string;
  logs: string[];
  expoTokenMasked: string;
  createdAt: Date;
}

const BuildSchema: Schema = new Schema({
  projectName: { type: String, required: true },
  slug: { type: String, required: true },
  bundleIdentifier: { type: String, required: true },
  status: { 
    type: String, 
    enum: ['pending', 'running', 'completed', 'failed'], 
    default: 'pending' 
  },
  buildUrl: { type: String },
  logs: { type: [String], default: [] },
  expoTokenMasked: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

export default mongoose.model<IBuild>('Build', BuildSchema);

/**
 * @fileoverview Express Application Setup
 * 
 * Main application configuration.
 * 
 * @module app
 */

import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import authRoutes from './src/routes/authentication.route.js';
import { corsAuth } from './src/middlewares/authentication.middleware.js';

dotenv.config();

const app = express();

// ============================================
// GLOBAL MIDDLEWARE (Applied to ALL routes)
// ============================================

app.use(helmet());                              // Security headers
app.use(express.json());                        // Parse JSON bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies
app.use(cookieParser());                        // Parse cookies

// CORS configuration
app.use(cors({
    origin: process.env.CORS_ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true
}));

// ============================================
// ROUTE-SPECIFIC MIDDLEWARE
// ============================================

// Apply corsAuth to auth routes only
app.use('/api/auth', corsAuth, authRoutes);

// ============================================
// OTHER ROUTES
// ============================================

// Public routes (no auth needed)
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok' });
});

export default app;
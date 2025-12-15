/**
 * @fileoverview Authentication Routes
 * 
 * Maps HTTP endpoints to controllers with appropriate middleware.
 * 
 * @module routes/auth/authenticationRoutes
 */

import express from 'express';
import AuthenticationController from '../controllers/authentication.controller.js';
import { 
    verifyAuth,
    requireAuth,
    optionalAuth,
    attachUserInfo,
    rateLimitAuth,
    validateRequestBody,
    corsAuth
} from '../middlewares/authentication.middleware.js';

const router = express.Router();
const authController = new AuthenticationController();

// ============================================
// PUBLIC ROUTES (No Authentication Required)
// ============================================

/**
 * Register new user
 * POST /api/auth/register
 */
router.post('/register',
    rateLimitAuth,                              // ← Rate limiting
    validateRequestBody(['name', 'email', 'password']), // ← Validation
    (req, res) => authController.register(req, res)
);

/**
 * Login user
 * POST /api/auth/login
 */
router.post('/login',
    rateLimitAuth,                              // ← Rate limiting
    validateRequestBody(['email', 'password']), // ← Validation
    (req, res) => authController.login(req, res)
);

/**
 * Verify token (can be used by frontend)
 * GET /api/auth/verify
 */
router.get('/verify',
    verifyAuth,                                 // ← Authentication required
    (req, res) => authController.verifyToken(req, res)
);

// ============================================
// PROTECTED ROUTES (Authentication Required)
// ============================================

/**
 * Logout current session
 * POST /api/auth/logout
 */
router.post('/logout',
    verifyAuth,                                 // ← Authentication required
    (req, res) => authController.logout(req, res)
);

/**
 * Get all active sessions
 * GET /api/auth/sessions
 */
router.get('/sessions',
    verifyAuth,                                 // ← Authentication required
    (req, res) => authController.getActiveSessions(req, res)
);

/**
 * Logout from all devices
 * POST /api/auth/logout/all
 */
router.post('/logout/all',
    verifyAuth,                                 // ← Authentication required
    (req, res) => authController.logoutAllDevices(req, res)
);

/**
 * Change password
 * PUT /api/auth/password
 */
router.put('/password',
    verifyAuth,                                 // ← Authentication required
    validateRequestBody(['newPassword']),       // ← Validation
    (req, res) => authController.changePassword(req, res)
);

// ============================================
// USER PROFILE ROUTES (With User Info)
// ============================================

/**
 * Get user profile
 * GET /api/auth/profile
 */
router.get('/profile',
    verifyAuth,                                 // ← Authentication required
    attachUserInfo,                             // ← Attach full user data
    (req, res) => {
        res.json({
            success: true,
            user: req.user  // Full user object available
        });
    }
);

export default router;
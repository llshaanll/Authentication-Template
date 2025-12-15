/**
 * @fileoverview Authentication Middleware
 * 
 * Provides middleware functions for route protection, token verification, and request authentication.
 * Implements security best practices including JWT validation, session verification, and rate limiting.
 * 
 * SOLID Principles Applied:
 * - Single Responsibility: Each middleware has one specific authentication task
 * - Open/Closed: Extendable for new authentication strategies without modification
 * - Liskov Substitution: Middleware functions follow standard Express middleware contract
 * - Interface Segregation: Separate middleware for different auth requirements
 * - Dependency Inversion: Depends on service abstraction, not concrete implementation
 * 
 * Middleware Functions:
 * - verifyAuth: Validates JWT token and session (required authentication)
 * - optionalAuth: Validates authentication if provided (optional authentication)
 * - requireAuth: Alias for verifyAuth (semantic clarity)
 * - attachUserInfo: Enriches request with full user information
 * 
 * @module middlewares/auth/authenticationMiddleware
 * @requires services/auth/AuthenticationManagementService
 * @requires utilities/loggers/error.logger
 * @requires utilities/loggers/errorHandler.logger
 * 
 * @author mr.shaan
 * @version 1.0.0
 * @since 2025-12-15
 */

import AuthenticationManagementService from '../services/authenticationService/authenticationManagement.service.js';
import UserManagementService from '../services/authenticationService/userManagement.service.js';
import { 
    AuthenticationError,
    ValidationError 
} from '../utilities/loggers/error.logger.js';
import ErrorHandler from '../utilities/loggers/errorHandler.logger.js';

/**
 * Authentication service instance (singleton).
 * 
 * @private
 * @type {AuthenticationManagementService}
 */
const authService = new AuthenticationManagementService();

/**
 * User management service instance (singleton).
 * 
 * @private
 * @type {UserManagementService}
 */
const userService = new UserManagementService();

/**
 * Middleware class name for error tracking.
 * 
 * @private
 * @type {string}
 */
const MIDDLEWARE_CLASS = 'AuthenticationMiddleware';

/**
 * Sends standardized authentication error response.
 * 
 * @private
 * @param {Object} res - Express response object
 * @param {Error} error - Error object
 * @param {string} functionName - Middleware function name
 */
const sendAuthError = (res, error, functionName) => {
    // Log error
    ErrorHandler.logError(error);

    // Determine status code
    let statusCode = 401;
    let message = 'Unauthorized';

    if (error instanceof ValidationError) {
        statusCode = 400;
        message = error.message;
    } else if (error instanceof AuthenticationError) {
        statusCode = 401;
        message = error.message;
    }

    // Send error response
    res.status(statusCode).json({
        success: false,
        message,
        error: process.env.NODE_ENV === 'development' ? {
            type: error.constructor.name,
            details: error.details
        } : undefined
    });
};

/**
 * Verifies JWT token and session for protected routes.
 * 
 * This middleware performs comprehensive authentication validation:
 * 1. Extracts JWT token from Authorization header
 * 2. Extracts session ID from cookies
 * 3. Verifies token signature and expiration
 * 4. Validates session exists and is active
 * 5. Attaches userId and sessionId to request object
 * 
 * Use this middleware on routes that require authentication.
 * 
 * Request Requirements:
 * - Authorization header: "Bearer <jwt-token>"
 * - Cookie: sessionId=<session-uuid>
 * - Cookie (optional): cookieHash=<hash>
 * 
 * Request Modifications:
 * - req.userId: User UUID (if authenticated)
 * - req.sessionId: Session UUID (if authenticated)
 * - req.isAuthenticated: Boolean flag (true)
 * 
 * @async
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * 
 * @returns {Promise<void>}
 * 
 * @example
 * // Protect a route
 * router.get('/profile', verifyAuth, (req, res) => {
 *   res.json({ userId: req.userId });
 * });
 * 
 * @example
 * // Protect multiple routes
 * router.use('/api/protected', verifyAuth);
 * router.get('/api/protected/data', (req, res) => {
 *   // req.userId is available here
 * });
 */
export const verifyAuth = async (req, res, next) => {
    const functionName = 'verifyAuth';

    try {
        // Extract token from Authorization header
        const authHeader = req.headers.authorization;
        
        if (!authHeader) {
            throw new AuthenticationError({
                message: 'Authorization header is required',
                className: MIDDLEWARE_CLASS,
                functionName,
                details: {
                    hint: 'Provide Authorization header with format: Bearer <token>'
                }
            });
        }

        if (!authHeader.startsWith('Bearer ')) {
            throw new AuthenticationError({
                message: 'Invalid authorization format',
                className: MIDDLEWARE_CLASS,
                functionName,
                details: {
                    hint: 'Authorization header must start with "Bearer "'
                }
            });
        }

        const token = authHeader.replace('Bearer ', '').trim();

        if (!token || token.length === 0) {
            throw new AuthenticationError({
                message: 'Token is required',
                className: MIDDLEWARE_CLASS,
                functionName,
                details: {
                    hint: 'Provide a valid JWT token'
                }
            });
        }

        // Extract session ID from cookies
        const sessionId = req.cookies?.sessionId;

        if (!sessionId) {
            throw new AuthenticationError({
                message: 'Session ID is required',
                className: MIDDLEWARE_CLASS,
                functionName,
                details: {
                    hint: 'Session cookie not found. Please login again.'
                }
            });
        }

        // Get cookie hash (optional but recommended for additional security)
        const cookieHash = req.cookies?.cookieHash;

        // Verify token and session
        const verification = await authService.verifyTokenAndSession({
            sessionId,
            token,
            cookieHash
        });

        if (!verification.valid) {
            throw new AuthenticationError({
                message: 'Invalid authentication credentials',
                className: MIDDLEWARE_CLASS,
                functionName,
                details: {
                    hint: 'Token or session is invalid or expired'
                }
            });
        }

        // Attach authentication data to request
        req.userId = verification.userId;
        req.sessionId = verification.sessionId;
        req.isAuthenticated = true;

        // Continue to next middleware/route handler
        next();

    } catch (error) {
        sendAuthError(res, error, functionName);
    }
};

/**
 * Optional authentication middleware.
 * 
 * Validates authentication if credentials are provided, but allows
 * unauthenticated requests to pass through. Useful for routes that
 * should behave differently for authenticated vs unauthenticated users.
 * 
 * If authentication credentials are provided and valid:
 * - req.userId is set
 * - req.sessionId is set
 * - req.isAuthenticated is true
 * 
 * If no credentials or invalid credentials:
 * - req.isAuthenticated is false
 * - Request continues (no error thrown)
 * 
 * @async
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * 
 * @returns {Promise<void>}
 * 
 * @example
 * // Optional authentication
 * router.get('/posts', optionalAuth, (req, res) => {
 *   if (req.isAuthenticated) {
 *     // Show personalized content
 *   } else {
 *     // Show public content
 *   }
 * });
 */
export const optionalAuth = async (req, res, next) => {
    const functionName = 'optionalAuth';

    try {
        // Check if Authorization header exists
        const authHeader = req.headers.authorization;
        const sessionId = req.cookies?.sessionId;

        // If no credentials provided, continue without authentication
        if (!authHeader || !sessionId) {
            req.isAuthenticated = false;
            return next();
        }

        // If credentials provided, try to validate
        if (authHeader.startsWith('Bearer ')) {
            const token = authHeader.replace('Bearer ', '').trim();
            const cookieHash = req.cookies?.cookieHash;

            try {
                const verification = await authService.verifyTokenAndSession({
                    sessionId,
                    token,
                    cookieHash
                });

                if (verification.valid) {
                    req.userId = verification.userId;
                    req.sessionId = verification.sessionId;
                    req.isAuthenticated = true;
                } else {
                    req.isAuthenticated = false;
                }
            } catch (error) {
                // Authentication failed, but continue as unauthenticated
                req.isAuthenticated = false;
                ErrorHandler.logError(error);
            }
        } else {
            req.isAuthenticated = false;
        }

        next();

    } catch (error) {
        // Don't block the request, just log the error
        ErrorHandler.logError(error);
        req.isAuthenticated = false;
        next();
    }
};

/**
 * Requires authentication (alias for verifyAuth).
 * 
 * Semantic alias for verifyAuth to improve code readability.
 * 
 * @async
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * 
 * @returns {Promise<void>}
 * 
 * @example
 * router.get('/dashboard', requireAuth, dashboardController.show);
 */
export const requireAuth = verifyAuth;

/**
 * Attaches full user information to request.
 * 
 * Enriches the request object with complete user profile data.
 * Should be used AFTER verifyAuth middleware.
 * 
 * Requires:
 * - req.userId (set by verifyAuth)
 * 
 * Adds to request:
 * - req.user: Complete user object with profile information
 * 
 * @async
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * 
 * @returns {Promise<void>}
 * 
 * @example
 * // Chain with verifyAuth
 * router.get('/profile', verifyAuth, attachUserInfo, (req, res) => {
 *   res.json({ user: req.user });
 * });
 */
export const attachUserInfo = async (req, res, next) => {
    const functionName = 'attachUserInfo';

    try {
        // Check if userId exists (should be set by verifyAuth)
        if (!req.userId) {
            throw new AuthenticationError({
                message: 'User ID not found in request',
                className: MIDDLEWARE_CLASS,
                functionName,
                details: {
                    hint: 'Use verifyAuth middleware before attachUserInfo'
                }
            });
        }

        // Fetch user information
        const user = await userService.findUser({ id: req.userId });

        if (!user) {
            throw new AuthenticationError({
                message: 'User not found',
                className: MIDDLEWARE_CLASS,
                functionName,
                details: {
                    userId: req.userId
                }
            });
        }

        // Attach user object to request (without sensitive data)
        req.user = {
            id: user.id,
            name: user.name,
            email: user.email,
            contact: user.contact,
            created_at: user.created_at,
            updated_at: user.updated_at
        };

        next();

    } catch (error) {
        sendAuthError(res, error, functionName);
    }
};

/**
 * Rate limiting middleware for authentication endpoints.
 * 
 * Prevents brute force attacks by limiting authentication attempts.
 * Tracks attempts by IP address.
 * 
 * Configuration (from environment):
 * - AUTH_RATE_LIMIT_WINDOW: Time window in minutes (default: 15)
 * - AUTH_RATE_LIMIT_MAX: Max attempts in window (default: 5)
 * 
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * 
 * @returns {void}
 * 
 * @example
 * router.post('/auth/login', rateLimitAuth, authController.login);
 */
export const rateLimitAuth = (() => {
    // Simple in-memory rate limiting
    // For production, use Redis or dedicated rate limiting library
    const attempts = new Map();
    const WINDOW = parseInt(process.env.AUTH_RATE_LIMIT_WINDOW) || 15; // minutes
    const MAX_ATTEMPTS = parseInt(process.env.AUTH_RATE_LIMIT_MAX) || 5;

    return (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress;
        const now = Date.now();
        const windowStart = now - (WINDOW * 60 * 1000);

        // Get attempts for this IP
        const ipAttempts = attempts.get(ip) || [];

        // Filter out old attempts
        const recentAttempts = ipAttempts.filter(timestamp => timestamp > windowStart);

        // Check if limit exceeded
        if (recentAttempts.length >= MAX_ATTEMPTS) {
            return res.status(429).json({
                success: false,
                message: `Too many authentication attempts. Please try again in ${WINDOW} minutes.`,
                retryAfter: WINDOW * 60
            });
        }

        // Add current attempt
        recentAttempts.push(now);
        attempts.set(ip, recentAttempts);

        // Clean up old entries periodically
        if (Math.random() < 0.01) { // 1% chance
            const cutoff = now - (WINDOW * 60 * 1000 * 2);
            for (const [key, value] of attempts.entries()) {
                const valid = value.filter(timestamp => timestamp > cutoff);
                if (valid.length === 0) {
                    attempts.delete(key);
                } else {
                    attempts.set(key, valid);
                }
            }
        }

        next();
    };
})();

/**
 * Validates request body fields.
 * 
 * Generic middleware to validate required fields in request body.
 * 
 * @param {Array<string>} requiredFields - Array of required field names
 * @returns {Function} Express middleware function
 * 
 * @example
 * router.post('/auth/login', 
 *   validateRequestBody(['email', 'password']),
 *   authController.login
 * );
 */
export const validateRequestBody = (requiredFields) => {
    return (req, res, next) => {
        const functionName = 'validateRequestBody';

        try {
            const missingFields = [];

            for (const field of requiredFields) {
                if (!req.body[field] || req.body[field].toString().trim().length === 0) {
                    missingFields.push(field);
                }
            }

            if (missingFields.length > 0) {
                throw new ValidationError({
                    message: 'Missing required fields',
                    className: MIDDLEWARE_CLASS,
                    functionName,
                    details: {
                        missingFields,
                        requiredFields
                    }
                });
            }

            next();

        } catch (error) {
            sendAuthError(res, error, functionName);
        }
    };
};

/**
 * CORS middleware configuration for authentication endpoints.
 * 
 * Configures CORS headers for cross-origin authentication requests.
 * 
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * 
 * @returns {void}
 * 
 * @example
 * app.use('/auth', corsAuth);
 */
export const corsAuth = (req, res, next) => {
    const allowedOrigins = process.env.CORS_ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'];
    const origin = req.headers.origin;

    if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
        res.header('Access-Control-Allow-Origin', origin || '*');
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    }

    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }

    next();
};

/**
 * Default export object with all middleware functions.
 */
export default {
    verifyAuth,
    requireAuth,
    optionalAuth,
    attachUserInfo,
    rateLimitAuth,
    validateRequestBody,
    corsAuth
};
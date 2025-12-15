/**
 * @fileoverview Authentication Controller
 * 
 * Handles HTTP requests for authentication operations including user registration,
 * login, logout, and token verification. Provides RESTful API endpoints with
 * comprehensive error handling, request validation, and standardized responses.
 * 
 * SOLID Principles Applied:
 * - Single Responsibility: Handles HTTP layer for authentication only
 * - Open/Closed: Extendable for new endpoints without modification
 * - Liskov Substitution: Can be replaced with any HTTP controller implementation
 * - Interface Segregation: Focused interface for authentication endpoints
 * - Dependency Inversion: Depends on service abstraction, not concrete implementation
 * 
 * Controller Responsibilities:
 * - HTTP request/response handling
 * - Request data extraction and validation
 * - Cookie management
 * - HTTP status code management
 * - Response formatting
 * - Error translation to HTTP responses
 * 
 * @module controllers/auth/AuthenticationController
 * @requires services/auth/AuthenticationManagementService
 * @requires utilities/loggers/error.logger
 * @requires utilities/loggers/errorHandler.logger
 * 
 * @author mr.shaan
 * @version 1.0.0
 * @since 2025-12-15
 */

import AuthenticationManagementService from '../services/authenticationService/authenticationManagement.service.js';
import { 
    ValidationError, 
    AuthenticationError,
    BusinessLogicError,
    NotFoundError
} from '../utilities/loggers/error.logger.js';
import ErrorHandler from '../utilities/loggers/errorHandler.logger.js';

/**
 * Controller class for Authentication HTTP endpoints.
 * 
 * Provides RESTful API endpoints for:
 * - User registration (POST /auth/register)
 * - User login (POST /auth/login)
 * - User logout (POST /auth/logout)
 * - Token verification (GET /auth/verify)
 * - Session management
 * 
 * @class AuthenticationController
 * 
 * @example
 * // Initialize controller
 * const authController = new AuthenticationController();
 * 
 * // Use in Express router
 * router.post('/auth/register', (req, res) => authController.register(req, res));
 * router.post('/auth/login', (req, res) => authController.login(req, res));
 */
class AuthenticationController {
    /**
     * Creates a new AuthenticationController instance.
     * 
     * Initializes authentication service dependency.
     * 
     * @constructor
     * 
     * @example
     * const authController = new AuthenticationController();
     */
    constructor() {
        /**
         * Authentication management service instance.
         * 
         * @private
         * @type {AuthenticationManagementService}
         */
        this.authService = new AuthenticationManagementService();

        /**
         * Class name for error tracking.
         * 
         * @private
         * @type {string}
         */
        this.className = 'AuthenticationController';

        /**
         * Cookie configuration.
         * 
         * @private
         * @type {Object}
         */
        this.COOKIE_OPTIONS = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        };
    }

    /**
     * Sends standardized success response.
     * 
     * @private
     * @param {Object} res - Express response object
     * @param {number} statusCode - HTTP status code
     * @param {string} message - Success message
     * @param {Object} [data] - Response data
     */
    _sendSuccess(res, statusCode, message, data = null) {
        const response = {
            success: true,
            message
        };

        if (data) {
            response.data = data;
        }

        res.status(statusCode).json(response);
    }

    /**
     * Sends standardized error response.
     * 
     * Translates service layer errors to appropriate HTTP responses.
     * 
     * @private
     * @param {Object} res - Express response object
     * @param {Error} error - Error object
     * @param {Object} [context] - Additional error context
     */
    _sendError(res, error, context = {}) {
        // Log error
        ErrorHandler.logError(error);

        // Determine status code based on error type
        let statusCode = 500;
        let message = 'Internal server error';

        if (error instanceof ValidationError) {
            statusCode = 400;
            message = error.message;
        } else if (error instanceof AuthenticationError) {
            statusCode = 401;
            message = error.message;
        } else if (error instanceof NotFoundError) {
            statusCode = 404;
            message = error.message;
        } else if (error instanceof BusinessLogicError) {
            statusCode = 400;
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
    }

    /**
     * Handles user registration.
     * 
     * POST /auth/register
     * 
     * Request Body:
     * - name: string (required)
     * - email: string (required)
     * - password: string (required)
     * - contact: string (optional)
     * 
     * @async
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * 
     * @returns {Promise<void>}
     * 
     * @example
     * POST /auth/register
     * Content-Type: application/json
     * 
     * {
     *   "name": "John Doe",
     *   "email": "john@example.com",
     *   "password": "SecurePass123!",
     *   "contact": "+1234567890"
     * }
     * 
     * Response 201:
     * {
     *   "success": true,
     *   "message": "Registration successful. Please login to continue.",
     *   "data": {
     *     "id": "uuid",
     *     "name": "John Doe",
     *     "email": "john@example.com",
     *     "contact": "+1234567890"
     *   }
     * }
     */
    async register(req, res) {
        const functionName = 'register';

        try {
            const { name, email, password, contact } = req.body;

            // Register user
            const newUser = await this.authService.registerUser({
                name,
                email,
                password,
                contact
            });

            // Send success response
            this._sendSuccess(
                res,
                201,
                'Registration successful. Please login to continue.',
                {
                    id: newUser.id,
                    name: newUser.name,
                    email: newUser.email,
                    contact: newUser.contact
                }
            );

        } catch (error) {
            this._sendError(res, error, {
                controller: this.className,
                action: functionName,
                ip: req.ip
            });
        }
    }

    /**
     * Handles user login.
     * 
     * POST /auth/login
     * 
     * Request Body:
     * - email: string (required)
     * - password: string (required)
     * 
     * Sets cookies:
     * - sessionId: Session identifier
     * - cookieHash: Cookie validation hash
     * 
     * @async
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * 
     * @returns {Promise<void>}
     * 
     * @example
     * POST /auth/login
     * Content-Type: application/json
     * 
     * {
     *   "email": "john@example.com",
     *   "password": "SecurePass123!"
     * }
     * 
     * Response 200:
     * {
     *   "success": true,
     *   "message": "Login successful",
     *   "data": {
     *     "token": "jwt-token",
     *     "user": {
     *       "id": "uuid",
     *       "name": "John Doe",
     *       "email": "john@example.com"
     *     }
     *   }
     * }
     */
    async login(req, res) {
        const functionName = 'login';

        try {
            const { email, password } = req.body;

            // Get device information
            const deviceIp = req.ip || req.connection.remoteAddress || '127.0.0.1';
            const userAgent = req.headers['user-agent'] || 'Unknown';

            // Authenticate user
            const loginResult = await this.authService.login({
                email,
                password,
                deviceIp,
                userAgent
            });

            // Set session cookies
            res.cookie('sessionId', loginResult.session.sessionId, this.COOKIE_OPTIONS);
            res.cookie('cookieHash', loginResult.session.cookieHash, this.COOKIE_OPTIONS);

            // Send success response with token
            this._sendSuccess(
                res,
                200,
                'Login successful',
                {
                    token: loginResult.session.token,
                    expiresAt: loginResult.session.expiresAt,
                    user: {
                        id: loginResult.user.id,
                        name: loginResult.user.name,
                        email: loginResult.user.email,
                        contact: loginResult.user.contact
                    }
                }
            );

        } catch (error) {
            this._sendError(res, error, {
                controller: this.className,
                action: functionName,
                ip: req.ip
            });
        }
    }

    /**
     * Handles user logout.
     * 
     * POST /auth/logout
     * 
     * Requires:
     * - sessionId cookie or Authorization header
     * 
     * Clears cookies:
     * - sessionId
     * - cookieHash
     * 
     * @async
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * 
     * @returns {Promise<void>}
     * 
     * @example
     * POST /auth/logout
     * Cookie: sessionId=session-uuid
     * 
     * Response 200:
     * {
     *   "success": true,
     *   "message": "Logged out successfully"
     * }
     */
    async logout(req, res) {
        const functionName = 'logout';

        try {
            // Get session ID from cookie or request
            const sessionId = req.cookies.sessionId || req.sessionId;

            if (!sessionId) {
                throw new ValidationError({
                    message: 'Session ID is required',
                    className: this.className,
                    functionName,
                    details: {
                        hint: 'Provide sessionId cookie or set req.sessionId in middleware'
                    }
                });
            }

            // Logout user
            await this.authService.logout(sessionId);

            // Clear cookies
            res.clearCookie('sessionId', this.COOKIE_OPTIONS);
            res.clearCookie('cookieHash', this.COOKIE_OPTIONS);

            // Send success response
            this._sendSuccess(
                res,
                200,
                'Logged out successfully'
            );

        } catch (error) {
            this._sendError(res, error, {
                controller: this.className,
                action: functionName,
                ip: req.ip
            });
        }
    }

    /**
     * Verifies JWT token and session.
     * 
     * GET /auth/verify
     * 
     * Requires:
     * - Authorization header with Bearer token
     * - sessionId cookie
     * 
     * This endpoint is typically called by frontend on app load
     * or by middleware on protected routes.
     * 
     * @async
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * 
     * @returns {Promise<void>}
     * 
     * @example
     * GET /auth/verify
     * Authorization: Bearer jwt-token
     * Cookie: sessionId=session-uuid
     * 
     * Response 200:
     * {
     *   "success": true,
     *   "message": "Token and session are valid",
     *   "data": {
     *     "valid": true,
     *     "userId": "uuid"
     *   }
     * }
     */
    async verifyToken(req, res) {
        const functionName = 'verifyToken';

        try {
            // Extract token from Authorization header
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                throw new AuthenticationError({
                    message: 'Authorization token is required',
                    className: this.className,
                    functionName,
                    details: {
                        hint: 'Provide token in Authorization header as "Bearer <token>"'
                    }
                });
            }

            const token = authHeader.replace('Bearer ', '');

            // Get session ID from cookie
            const sessionId = req.cookies.sessionId;
            if (!sessionId) {
                throw new AuthenticationError({
                    message: 'Session ID is required',
                    className: this.className,
                    functionName,
                    details: {
                        hint: 'Provide sessionId in cookie'
                    }
                });
            }

            // Get cookie hash (optional but recommended)
            const cookieHash = req.cookies.cookieHash;

            // Verify token and session
            const verification = await this.authService.verifyTokenAndSession({
                sessionId,
                token,
                cookieHash
            });

            // Send success response
            this._sendSuccess(
                res,
                200,
                'Token and session are valid',
                {
                    valid: verification.valid,
                    userId: verification.userId
                }
            );

        } catch (error) {
            this._sendError(res, error, {
                controller: this.className,
                action: functionName,
                ip: req.ip
            });
        }
    }

    /**
     * Gets all active sessions for authenticated user.
     * 
     * GET /auth/sessions
     * 
     * Requires authentication (use verifyToken middleware).
     * 
     * @async
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * 
     * @returns {Promise<void>}
     * 
     * @example
     * GET /auth/sessions
     * Authorization: Bearer jwt-token
     * 
     * Response 200:
     * {
     *   "success": true,
     *   "message": "Active sessions retrieved",
     *   "data": {
     *     "sessions": [
     *       {
     *         "sessionId": "uuid",
     *         "deviceIp": "192.168.1.1",
     *         "userAgent": "Mozilla/5.0...",
     *         "createdAt": "2025-12-15T10:00:00Z",
     *         "lastUsed": "2025-12-15T14:00:00Z"
     *       }
     *     ],
     *     "count": 1
     *   }
     * }
     */
    async getActiveSessions(req, res) {
        const functionName = 'getActiveSessions';

        try {
            // Get userId from request (set by auth middleware)
            const userId = req.userId;

            if (!userId) {
                throw new AuthenticationError({
                    message: 'User ID not found in request',
                    className: this.className,
                    functionName,
                    details: {
                        hint: 'Use authentication middleware to set req.userId'
                    }
                });
            }

            // Get active sessions
            const sessions = await this.authService.getActiveSessions(userId);

            // Send success response
            this._sendSuccess(
                res,
                200,
                'Active sessions retrieved',
                {
                    sessions,
                    count: sessions.length
                }
            );

        } catch (error) {
            this._sendError(res, error, {
                controller: this.className,
                action: functionName,
                ip: req.ip
            });
        }
    }

    /**
     * Logs out user from all devices.
     * 
     * POST /auth/logout/all
     * 
     * Requires authentication (use verifyToken middleware).
     * Terminates all active sessions for the user.
     * 
     * @async
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * 
     * @returns {Promise<void>}
     * 
     * @example
     * POST /auth/logout/all
     * Authorization: Bearer jwt-token
     * 
     * Response 200:
     * {
     *   "success": true,
     *   "message": "Logged out from 3 device(s)"
     * }
     */
    async logoutAllDevices(req, res) {
        const functionName = 'logoutAllDevices';

        try {
            // Get userId from request (set by auth middleware)
            const userId = req.userId;

            if (!userId) {
                throw new AuthenticationError({
                    message: 'User ID not found in request',
                    className: this.className,
                    functionName,
                    details: {
                        hint: 'Use authentication middleware to set req.userId'
                    }
                });
            }

            // Logout from all devices
            const result = await this.authService.logoutAllDevices(userId);

            // Clear cookies for current device
            res.clearCookie('sessionId', this.COOKIE_OPTIONS);
            res.clearCookie('cookieHash', this.COOKIE_OPTIONS);

            // Send success response
            this._sendSuccess(
                res,
                200,
                result.message
            );

        } catch (error) {
            this._sendError(res, error, {
                controller: this.className,
                action: functionName,
                ip: req.ip
            });
        }
    }

    /**
     * Changes user password.
     * 
     * PUT /auth/password
     * 
     * Requires authentication (use verifyToken middleware).
     * Logs out user from all devices after password change.
     * 
     * @async
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * 
     * @returns {Promise<void>}
     * 
     * @example
     * PUT /auth/password
     * Authorization: Bearer jwt-token
     * Content-Type: application/json
     * 
     * {
     *   "newPassword": "NewSecurePass456!"
     * }
     * 
     * Response 200:
     * {
     *   "success": true,
     *   "message": "Password changed successfully. Please login again."
     * }
     */
    async changePassword(req, res) {
        const functionName = 'changePassword';

        try {
            const { newPassword } = req.body;

            // Get userId from request (set by auth middleware)
            const userId = req.userId;

            if (!userId) {
                throw new AuthenticationError({
                    message: 'User ID not found in request',
                    className: this.className,
                    functionName,
                    details: {
                        hint: 'Use authentication middleware to set req.userId'
                    }
                });
            }

            // Change password
            const result = await this.authService.changePassword(userId, newPassword);

            // Clear cookies
            res.clearCookie('sessionId', this.COOKIE_OPTIONS);
            res.clearCookie('cookieHash', this.COOKIE_OPTIONS);

            // Send success response
            this._sendSuccess(
                res,
                200,
                result.message
            );

        } catch (error) {
            this._sendError(res, error, {
                controller: this.className,
                action: functionName,
                ip: req.ip
            });
        }
    }
}

export default AuthenticationController;
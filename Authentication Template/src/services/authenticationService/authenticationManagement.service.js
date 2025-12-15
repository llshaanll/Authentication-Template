/**
 * @fileoverview Authentication Management Service
 * 
 * Provides high-level business logic for complete authentication workflows.
 * Orchestrates UserManagementService and SessionManagementService to deliver
 * end-to-end authentication flows including registration, login, logout, and verification.
 * 
 * SOLID Principles Applied:
 * - Single Responsibility: Orchestrates authentication workflows only
 * - Open/Closed: Extendable for OAuth, 2FA without modification
 * - Liskov Substitution: Can be replaced with any IAuthenticationService implementation
 * - Interface Segregation: Focused interface for authentication flows only
 * - Dependency Inversion: Depends on service abstractions, not concrete implementations
 * 
 * Service Responsibilities:
 * - User registration orchestration
 * - Login flow coordination
 * - Logout flow coordination
 * - Token and session validation
 * - Activity status management
 * - Security enforcement
 * 
 * @module services/auth/AuthenticationManagementService
 * @requires services/user/UserManagementService
 * @requires services/session/SessionManagementService
 * @requires utilities/loggers/error.logger
 * @requires utilities/loggers/errorHandler.logger
 * @requires validators/SecurityValidator
 * 
 * @author mr.shaan
 * @version 1.0.0
 * @since 2025-12-15
 */

import UserManagementService from './userManagement.service.js';
import SessionManagementService from './sessionManagement.service.js';
import { 
    ValidationError, 
    AuthenticationError,
    BusinessLogicError
} from '../../utilities/loggers/error.logger.js';
import ErrorHandler from '../../utilities/loggers/errorHandler.logger.js';
import SecurityValidator from '../../utilities/validators/security.validator.js';

/**
 * Service class for Authentication Management business logic.
 * 
 * Orchestrates complete authentication workflows:
 * - User registration with automatic account setup
 * - Secure login with session creation
 * - Comprehensive logout with cleanup
 * - Token and session validation
 * - Multi-service coordination
 * 
 * @class AuthenticationManagementService
 * 
 * @example
 * // Initialize service
 * const authService = new AuthenticationManagementService();
 * 
 * // Register new user
 * const user = await authService.registerUser({
 *   name: 'John Doe',
 *   email: 'john@example.com',
 *   password: 'SecurePass123!'
 * });
 * 
 * @example
 * // Login user
 * const session = await authService.login({
 *   email: 'john@example.com',
 *   password: 'SecurePass123!',
 *   deviceIp: '192.168.1.1',
 *   userAgent: 'Mozilla/5.0...'
 * });
 */
class AuthenticationManagementService {
    /**
     * Creates a new AuthenticationManagementService instance.
     * 
     * Initializes dependent services and configuration.
     * Uses Dependency Injection for testability and flexibility.
     * 
     * @constructor
     * 
     * @example
     * const authService = new AuthenticationManagementService();
     */
    constructor() {
        /**
         * User management service instance.
         * 
         * @private
         * @type {UserManagementService}
         */
        this.userService = new UserManagementService();

        /**
         * Session management service instance.
         * 
         * @private
         * @type {SessionManagementService}
         */
        this.sessionService = new SessionManagementService();

        /**
         * Security validator instance for input validation.
         * 
         * @private
         * @type {SecurityValidator}
         */
        this.validator = new SecurityValidator();

        /**
         * Class name for error tracking.
         * 
         * @private
         * @type {string}
         */
        this.className = 'AuthenticationManagementService';
    }

    /**
     * Registers a new user account.
     * 
     * Orchestrates complete user registration flow:
     * 1. Validates registration data
     * 2. Checks email availability
     * 3. Creates user with password (via UserManagementService)
     * 4. Sets up activity tracking
     * 
     * Business Rules:
     * - Email must be unique
     * - Password must meet security requirements
     * - User starts with 'logged out' status
     * - No automatic login after registration
     * 
     * @async
     * @param {Object} registrationData - User registration data
     * @param {string} registrationData.name - User's full name
     * @param {string} registrationData.email - User's email address
     * @param {string} registrationData.password - Plain text password
     * @param {string} [registrationData.contact] - User's contact number (optional)
     * 
     * @returns {Promise<Object>} Created user object (without password)
     * @returns {string} return.id - Generated UUID for the user
     * @returns {string} return.name - User's name
     * @returns {string} return.email - User's email
     * @returns {string} [return.contact] - User's contact
     * @returns {Date} return.created_at - Account creation timestamp
     * 
     * @throws {ValidationError} If registration data is invalid
     * @throws {BusinessLogicError} If email already exists or registration fails
     * 
     * @example
     * const newUser = await authService.registerUser({
     *   name: 'John Doe',
     *   email: 'john@example.com',
     *   password: 'SecurePass123!',
     *   contact: '+1234567890'
     * });
     * 
     * console.log(`User registered: ${newUser.email}`);
     * // User must login to get session token
     */
    async registerUser(registrationData) {
        const functionName = 'registerUser';

        try {
            // Validate registration data
            if (!registrationData || typeof registrationData !== 'object') {
                throw new ValidationError({
                    message: 'Registration data must be an object',
                    className: this.className,
                    functionName,
                    details: {
                        receivedType: typeof registrationData
                    }
                });
            }

            const { email } = registrationData;

            // Check if email already exists
            const existingUser = await this.userService.userExistsByEmail(email);
            
            if (existingUser) {
                throw new BusinessLogicError({
                    message: 'Email address already registered',
                    className: this.className,
                    functionName,
                    details: {
                        email: email?.substring(0, 50),
                        hint: 'Use a different email or try logging in'
                    }
                });
            }

            // Create user account (includes password and activity setup)
            const newUser = await this.userService.createUserAndPassword(registrationData);

            // Return user without sensitive information
            return {
                id: newUser.id,
                name: newUser.name,
                email: newUser.email,
                contact: newUser.contact,
                created_at: newUser.created_at
            };

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof BusinessLogicError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'User registration failed',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    email: registrationData?.email?.substring(0, 50)
                }
            });

            ErrorHandler.logError(serviceError);
            throw serviceError;
        }
    }

    /**
     * Authenticates user and creates session.
     * 
     * Orchestrates complete login flow:
     * 1. Validates login credentials
     * 2. Finds user by email
     * 3. Verifies password
     * 4. Creates authenticated session
     * 5. Updates activity status to 'logged in'
     * 
     * Security Features:
     * - Bcrypt password comparison
     * - Device fingerprinting (IP, User Agent)
     * - JWT token generation
     * - Session tracking
     * - Activity logging
     * 
     * @async
     * @param {Object} loginData - Login credentials and device info
     * @param {string} loginData.email - User's email address
     * @param {string} loginData.password - Plain text password
     * @param {string} loginData.deviceIp - Client IP address
     * @param {string} loginData.userAgent - Client user agent string
     * 
     * @returns {Promise<Object>} Session data with authentication token
     * @returns {Object} return.user - User information (without password)
     * @returns {string} return.user.id - User UUID
     * @returns {string} return.user.name - User's name
     * @returns {string} return.user.email - User's email
     * @returns {Object} return.session - Session information
     * @returns {string} return.session.sessionId - Unique session identifier
     * @returns {string} return.session.token - JWT access token
     * @returns {string} return.session.cookieHash - Cookie validation hash
     * @returns {Date} return.session.expiresAt - Session expiration timestamp
     * 
     * @throws {ValidationError} If login data is invalid
     * @throws {AuthenticationError} If credentials are incorrect
     * @throws {BusinessLogicError} If login process fails
     * 
     * @example
     * const loginResult = await authService.login({
     *   email: 'john@example.com',
     *   password: 'SecurePass123!',
     *   deviceIp: req.ip,
     *   userAgent: req.headers['user-agent']
     * });
     * 
     * // Set session cookie
     * res.cookie('sessionId', loginResult.session.sessionId, {
     *   httpOnly: true,
     *   secure: true,
     *   maxAge: 24 * 60 * 60 * 1000
     * });
     * 
     * // Return token to client
     * res.json({ 
     *   token: loginResult.session.token,
     *   user: loginResult.user
     * });
     */
    async login(loginData) {
        const functionName = 'login';

        try {
            // Validate login data
            if (!loginData || typeof loginData !== 'object') {
                throw new ValidationError({
                    message: 'Login data must be an object',
                    className: this.className,
                    functionName,
                    details: {
                        receivedType: typeof loginData
                    }
                });
            }

            const { email, password, deviceIp, userAgent } = loginData;

            // Validate required fields
            if (!email || !password) {
                throw new ValidationError({
                    message: 'Email and password are required',
                    className: this.className,
                    functionName,
                    details: {
                        hasEmail: !!email,
                        hasPassword: !!password
                    }
                });
            }

            if (!deviceIp || !userAgent) {
                throw new ValidationError({
                    message: 'Device IP and User Agent are required for session tracking',
                    className: this.className,
                    functionName,
                    details: {
                        hasDeviceIp: !!deviceIp,
                        hasUserAgent: !!userAgent
                    }
                });
            }

            // Step 1: Find user by email
            const user = await this.userService.findUser({ email });

            if (!user) {
                throw new AuthenticationError({
                    message: 'Invalid email or password',
                    className: this.className,
                    functionName,
                    details: {
                        hint: 'User not found'
                    }
                });
            }

            // Step 2: Verify password
            const isPasswordValid = await this.userService.verifyPassword(user.id, password);

            if (!isPasswordValid) {
                throw new AuthenticationError({
                    message: 'Invalid email or password',
                    className: this.className,
                    functionName,
                    details: {
                        hint: 'Password mismatch'
                    }
                });
            }

            // Step 3: Create session (automatically updates activity to 'logged in')
            const session = await this.sessionService.createSession({
                userId: user.id,
                deviceIp,
                userAgent
            });

            // Return user and session data
            return {
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    contact: user.contact
                },
                session: {
                    sessionId: session.sessionId,
                    token: session.token,
                    cookieHash: session.cookieHash,
                    expiresAt: session.expiresAt
                }
            };

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof AuthenticationError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'Login failed',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    email: loginData?.email?.substring(0, 50)
                }
            });

            ErrorHandler.logError(serviceError);
            throw serviceError;
        }
    }

    /**
     * Logs out user and cleans up session.
     * 
     * Orchestrates complete logout flow:
     * 1. Validates session exists
     * 2. Deletes session from database
     * 3. Updates activity status if no other active sessions
     * 
     * The activity status is automatically managed by SessionManagementService.
     * If this is the last active session, status changes to 'logged out'.
     * If user has other active sessions, status remains 'logged in'.
     * 
     * @async
     * @param {string} sessionId - Unique session identifier to terminate
     * @param {string} [userId] - User UUID (optional, for validation)
     * 
     * @returns {Promise<Object>} Logout confirmation
     * @returns {boolean} return.success - Logout success status
     * @returns {string} return.message - Confirmation message
     * 
     * @throws {ValidationError} If sessionId is invalid
     * @throws {BusinessLogicError} If logout process fails
     * 
     * @example
     * // Logout current device
     * await authService.logout(req.sessionId);
     * 
     * // Clear cookies
     * res.clearCookie('sessionId');
     * res.clearCookie('token');
     * 
     * res.json({ message: 'Logged out successfully' });
     * 
     * @example
     * // Logout with user validation
     * await authService.logout(sessionId, userId);
     */
    async logout(sessionId, userId = null) {
        const functionName = 'logout';

        try {
            // Validate sessionId
            if (!sessionId || typeof sessionId !== 'string' || sessionId.trim().length === 0) {
                throw new ValidationError({
                    message: 'Session ID is required and must be a non-empty string',
                    className: this.className,
                    functionName,
                    details: {
                        field: 'sessionId',
                        receivedType: typeof sessionId
                    }
                });
            }

            // Delete session (automatically updates activity status)
            await this.sessionService.deleteSession(sessionId, userId);

            return {
                success: true,
                message: 'Logged out successfully'
            };

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'Logout failed',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    sessionId: sessionId?.substring(0, 50)
                }
            });

            ErrorHandler.logError(serviceError);
            throw serviceError;
        }
    }

    /**
     * Logs out user from all devices.
     * 
     * Terminates all active sessions for a user.
     * Useful for:
     * - Password change
     * - Security breach response
     * - Account settings change
     * 
     * @async
     * @param {string} userId - UUID of the user
     * 
     * @returns {Promise<Object>} Logout confirmation
     * @returns {boolean} return.success - Logout success status
     * @returns {number} return.sessionsTerminated - Number of sessions deleted
     * @returns {string} return.message - Confirmation message
     * 
     * @throws {ValidationError} If userId is invalid
     * @throws {BusinessLogicError} If logout process fails
     * 
     * @example
     * // Logout all devices
     * const result = await authService.logoutAllDevices(userId);
     * console.log(`Terminated ${result.sessionsTerminated} sessions`);
     */
    async logoutAllDevices(userId) {
        const functionName = 'logoutAllDevices';

        try {
            // Validate userId
            const validation = this.validator.validateUUID(userId, 'User ID');
            if (!validation.isValid) {
                throw new ValidationError({
                    message: validation.error,
                    className: this.className,
                    functionName,
                    details: {
                        received: userId,
                        receivedType: typeof userId
                    }
                });
            }

            // Delete all sessions (automatically updates activity to 'logged out')
            const sessionsTerminated = await this.sessionService.deleteAllUserSessions(
                validation.sanitized
            );

            return {
                success: true,
                sessionsTerminated,
                message: `Logged out from ${sessionsTerminated} device(s)`
            };

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'Logout all devices failed',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    userId: userId?.toString().substring(0, 50)
                }
            });

            ErrorHandler.logError(serviceError);
            throw serviceError;
        }
    }

    /**
     * Verifies JWT token and validates session.
     * 
     * Performs comprehensive authentication validation:
     * 1. Verifies JWT token signature and expiration
     * 2. Validates session exists in database
     * 3. Checks session is active and not expired
     * 4. Validates cookie hash (if provided)
     * 5. Updates session activity timestamp
     * 
     * This method should be called on every authenticated request
     * to ensure the user's session is valid.
     * 
     * @async
     * @param {Object} verificationData - Verification parameters
     * @param {string} verificationData.sessionId - Session identifier from cookie
     * @param {string} verificationData.token - JWT token from Authorization header
     * @param {string} [verificationData.cookieHash] - Cookie hash for validation (optional)
     * 
     * @returns {Promise<Object>} Validation result
     * @returns {boolean} return.valid - Whether authentication is valid
     * @returns {string} return.userId - User UUID
     * @returns {string} return.sessionId - Session identifier
     * 
     * @throws {ValidationError} If verification data is invalid
     * @throws {AuthenticationError} If token or session is invalid
     * @throws {BusinessLogicError} If verification process fails
     * 
     * @example
     * // Verify in authentication middleware
     * const verification = await authService.verifyTokenAndSession({
     *   sessionId: req.cookies.sessionId,
     *   token: req.headers.authorization?.replace('Bearer ', ''),
     *   cookieHash: req.cookies.cookieHash
     * });
     * 
     * if (!verification.valid) {
     *   return res.status(401).json({ error: 'Unauthorized' });
     * }
     * 
     * req.userId = verification.userId;
     * next();
     * 
     * @example
     * // Verify without cookie hash
     * const verification = await authService.verifyTokenAndSession({
     *   sessionId: req.cookies.sessionId,
     *   token: req.headers.authorization?.replace('Bearer ', '')
     * });
     */
    async verifyTokenAndSession(verificationData) {
        const functionName = 'verifyTokenAndSession';

        try {
            // Validate verification data
            if (!verificationData || typeof verificationData !== 'object') {
                throw new ValidationError({
                    message: 'Verification data must be an object',
                    className: this.className,
                    functionName,
                    details: {
                        receivedType: typeof verificationData
                    }
                });
            }

            const { sessionId, token, cookieHash } = verificationData;

            // Validate required fields
            if (!sessionId || !token) {
                throw new ValidationError({
                    message: 'Session ID and token are required',
                    className: this.className,
                    functionName,
                    details: {
                        hasSessionId: !!sessionId,
                        hasToken: !!token
                    }
                });
            }

            // Validate session and token
            const validation = await this.sessionService.validateSession(
                sessionId,
                token,
                cookieHash
            );

            return validation;

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof AuthenticationError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'Token and session verification failed',
                className: this.className,
                functionName,
                cause: error
            });

            ErrorHandler.logError(serviceError);
            throw serviceError;
        }
    }

    /**
     * Gets all active sessions for a user.
     * 
     * Retrieves list of all active sessions with device information.
     * Useful for:
     * - Account security dashboard
     * - Device management
     * - Session monitoring
     * 
     * @async
     * @param {string} userId - UUID of the user
     * 
     * @returns {Promise<Array>} Array of active sessions
     * 
     * @throws {ValidationError} If userId is invalid
     * @throws {BusinessLogicError} If retrieval fails
     * 
     * @example
     * const sessions = await authService.getActiveSessions(userId);
     * console.log(`User has ${sessions.length} active devices`);
     */
    async getActiveSessions(userId) {
        const functionName = 'getActiveSessions';

        try {
            return await this.sessionService.getActiveSessions(userId);

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'Failed to retrieve active sessions',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    userId: userId?.toString().substring(0, 50)
                }
            });

            ErrorHandler.logError(serviceError);
            throw serviceError;
        }
    }

    /**
     * Changes user password and invalidates all sessions.
     * 
     * Security best practice: When password changes, all existing
     * sessions should be terminated to prevent unauthorized access.
     * 
     * @async
     * @param {string} userId - UUID of the user
     * @param {string} newPassword - New plain text password
     * 
     * @returns {Promise<Object>} Password change confirmation
     * @returns {boolean} return.success - Change success status
     * @returns {number} return.sessionsTerminated - Number of sessions deleted
     * @returns {string} return.message - Confirmation message
     * 
     * @throws {ValidationError} If userId or password is invalid
     * @throws {BusinessLogicError} If password change fails
     * 
     * @example
     * const result = await authService.changePassword(userId, newPassword);
     * console.log(result.message);
     * // User must login again with new password
     */
    async changePassword(userId, newPassword) {
        const functionName = 'changePassword';

        try {
            // Update password
            await this.userService.updateUserPassword(userId, newPassword);

            // Logout from all devices for security
            const sessionsTerminated = await this.sessionService.deleteAllUserSessions(userId);

            return {
                success: true,
                sessionsTerminated,
                message: 'Password changed successfully. Please login again.'
            };

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'Password change failed',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    userId: userId?.toString().substring(0, 50)
                }
            });

            ErrorHandler.logError(serviceError);
            throw serviceError;
        }
    }
}

export default AuthenticationManagementService;

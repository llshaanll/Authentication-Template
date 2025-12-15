/**
 * @fileoverview Session Management Service
 * 
 * Provides business logic for user session lifecycle management and JWT-based authentication.
 * Implements the Service Layer Pattern to orchestrate session operations with secure
 * token generation, validation, and device tracking.
 * 
 * SOLID Principles Applied:
 * - Single Responsibility: Handles session management business logic only
 * - Open/Closed: Extendable for new session policies without modification
 * - Liskov Substitution: Can be replaced with any ISessionManagementService implementation
 * - Interface Segregation: Focused interface for session operations only
 * - Dependency Inversion: Depends on repository abstractions, not concrete implementations
 * 
 * Service Responsibilities:
 * - JWT token generation and verification
 * - Session creation with device fingerprinting
 * - Session validation and renewal
 * - Session termination (logout)
 * - Multi-device session management
 * - Cookie hash generation for validation
 * 
 * @module services/session/SessionManagementService
 * @requires repositories/user/UserSessionRepository
 * @requires repositories/user/UserActivityRepository
 * @requires config/database
 * @requires jsonwebtoken
 * @requires crypto
 * @requires utilities/loggers/error.logger
 * @requires utilities/loggers/errorHandler.logger
 * @requires validators/SecurityValidator
 * 
 * @author mr.shaan
 * @version 1.0.0
 * @since 2025-12-15
 */

import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import databaseInstance from '../../configuration/postgres/database.config.js';
import UserSessionRepository from '../../repositories/user/userSession.repository.js';
import UserActivityRepository from '../../repositories/user/userActivity.repository.js';
import { 
    ValidationError, 
    DatabaseError, 
    NotFoundError,
    AuthenticationError,
    BusinessLogicError
} from '../../utilities/loggers/error.logger.js';
import ErrorHandler from '../../utilities/loggers/errorHandler.logger.js';
import SecurityValidator from '../../utilities/validators/security.validator.js';

/**
 * Service class for Session Management business logic.
 * 
 * Manages authenticated sessions with:
 * - JWT token-based authentication
 * - Secure session storage and validation
 * - Device tracking and fingerprinting
 * - Session expiration management
 * - Multi-device support
 * 
 * @class SessionManagementService
 * 
 * @example
 * // Initialize service
 * const sessionService = new SessionManagementService();
 * 
 * // Create session after login
 * const session = await sessionService.createSession({
 *   userId: '550e8400-e29b-41d4-a716-446655440000',
 *   deviceIp: '192.168.1.1',
 *   userAgent: 'Mozilla/5.0...'
 * });
 * 
 * @example
 * // Validate session
 * const isValid = await sessionService.validateSession(sessionId, token);
 */
class SessionManagementService {
    /**
     * Creates a new SessionManagementService instance.
     * 
     * Initializes service dependencies and JWT configuration.
     * 
     * @constructor
     * @throws {ValidationError} If required environment variables are missing
     * 
     * @example
     * const sessionService = new SessionManagementService();
     */
    constructor() {
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
        this.className = 'SessionManagementService';

        /**
         * JWT secret key for token signing/verification.
         * 
         * @private
         * @type {string}
         */
        this.JWT_SECRET = process.env.JWT_SECRET;

        /**
         * JWT token expiration time.
         * 
         * @private
         * @type {string}
         */
        this.JWT_EXPIRATION = process.env.JWT_EXPIRATION || '24h';

        /**
         * Session TTL (Time To Live) in PostgreSQL interval format.
         * 
         * @private
         * @type {string}
         */
        this.SESSION_TTL = process.env.SESSION_TTL || '24 hours';

        // Validate JWT secret is configured
        if (!this.JWT_SECRET) {
            throw new ValidationError({
                message: 'JWT_SECRET environment variable is required',
                className: this.className,
                functionName: 'constructor',
                details: {
                    missing: 'JWT_SECRET',
                    hint: 'Set JWT_SECRET in your .env file'
                }
            });
        }
    }

    /**
     * Generates a JWT token for user authentication.
     * 
     * Creates a signed JWT containing user identification and metadata.
     * Token is used for stateless authentication across requests.
     * 
     * @private
     * @param {string} userId - UUID of the user
     * @param {string} sessionId - Unique session identifier
     * @returns {string} Signed JWT token
     * @throws {DatabaseError} If token generation fails
     * 
     * @example
     * const token = this._generateJWTToken(userId, sessionId);
     */
    _generateJWTToken(userId, sessionId) {
        const functionName = '_generateJWTToken';

        try {
            const payload = {
                userId,
                sessionId,
                type: 'access',
                iat: Math.floor(Date.now() / 1000)
            };

            return jwt.sign(payload, this.JWT_SECRET, {
                expiresIn: this.JWT_EXPIRATION,
                issuer: process.env.APP_NAME || 'authentication_app',
                audience: 'user'
            });

        } catch (error) {
            throw new DatabaseError({
                message: 'Failed to generate JWT token',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    hint: 'JWT signing operation failed'
                }
            });
        }
    }

    /**
     * Verifies and decodes a JWT token.
     * 
     * Validates token signature, expiration, and structure.
     * Returns decoded payload if valid.
     * 
     * @private
     * @param {string} token - JWT token to verify
     * @returns {Object} Decoded token payload
     * @returns {string} return.userId - User UUID from token
     * @returns {string} return.sessionId - Session ID from token
     * @returns {string} return.type - Token type
     * @returns {number} return.iat - Issued at timestamp
     * @returns {number} return.exp - Expiration timestamp
     * @throws {AuthenticationError} If token is invalid or expired
     * 
     * @example
     * const payload = this._verifyJWTToken(token);
     * console.log(`User: ${payload.userId}`);
     */
    _verifyJWTToken(token) {
        const functionName = '_verifyJWTToken';

        try {
            const decoded = jwt.verify(token, this.JWT_SECRET, {
                issuer: process.env.APP_NAME || 'authentication_app',
                audience: 'user'
            });

            return decoded;

        } catch (error) {
            // Handle specific JWT errors
            if (error.name === 'TokenExpiredError') {
                throw new AuthenticationError({
                    message: 'Token has expired',
                    className: this.className,
                    functionName,
                    cause: error,
                    details: {
                        expiredAt: error.expiredAt
                    }
                });
            }

            if (error.name === 'JsonWebTokenError') {
                throw new AuthenticationError({
                    message: 'Invalid token',
                    className: this.className,
                    functionName,
                    cause: error,
                    details: {
                        reason: error.message
                    }
                });
            }

            throw new AuthenticationError({
                message: 'Token verification failed',
                className: this.className,
                functionName,
                cause: error
            });
        }
    }

    /**
     * Generates a secure hash for cookie validation.
     * 
     * Creates SHA-256 hash of session ID and user ID for cookie integrity.
     * Used to validate session cookies and prevent tampering.
     * 
     * @private
     * @param {string} sessionId - Unique session identifier
     * @param {string} userId - User UUID
     * @returns {string} Hex-encoded SHA-256 hash
     * 
     * @example
     * const cookieHash = this._generateCookieHash(sessionId, userId);
     */
    _generateCookieHash(sessionId, userId) {
        const data = `${sessionId}:${userId}:${this.JWT_SECRET}`;
        return crypto.createHash('sha256').update(data).digest('hex');
    }

    /**
     * Generates a unique session ID.
     * 
     * Creates cryptographically secure random session identifier.
     * 
     * @private
     * @returns {string} Unique session ID
     * 
     * @example
     * const sessionId = this._generateSessionId();
     */
    _generateSessionId() {
        return crypto.randomUUID();
    }

    /**
     * Creates a new authenticated session with JWT token.
     * 
     * Performs atomic transaction to:
     * 1. Generate unique session ID
     * 2. Create JWT token
     * 3. Generate cookie hash
     * 4. Store session in database
     * 5. Update user activity status to 'logged in'
     * 
     * Session includes:
     * - JWT token for authentication
     * - Device fingerprinting (IP, User Agent)
     * - Automatic expiration based on TTL
     * - Cookie hash for validation
     * 
     * @async
     * @param {Object} sessionData - Session creation data
     * @param {string} sessionData.userId - UUID of the user
     * @param {string} sessionData.deviceIp - Client IP address (IPv4 or IPv6)
     * @param {string} sessionData.userAgent - Client user agent string
     * 
     * @returns {Promise<Object>} Created session with token
     * @returns {string} return.sessionId - Unique session identifier
     * @returns {string} return.token - JWT access token
     * @returns {string} return.cookieHash - Cookie validation hash
     * @returns {Date} return.expiresAt - Session expiration timestamp
     * @returns {string} return.userId - User UUID
     * 
     * @throws {ValidationError} If session data is invalid
     * @throws {DatabaseError} If database operation fails
     * @throws {BusinessLogicError} If session creation logic fails
     * 
     * @example
     * // Create session after successful login
     * const session = await sessionService.createSession({
     *   userId: '550e8400-e29b-41d4-a716-446655440000',
     *   deviceIp: req.ip || req.connection.remoteAddress,
     *   userAgent: req.headers['user-agent']
     * });
     * 
     * // Set cookie and return token
     * res.cookie('sessionId', session.sessionId, {
     *   httpOnly: true,
     *   secure: true,
     *   maxAge: 24 * 60 * 60 * 1000 // 24 hours
     * });
     * 
     * res.json({ token: session.token });
     * 
     * @example
     * // Create session with transaction
     * await databaseInstance.transaction(async (client) => {
     *   const sessionService = new SessionManagementService();
     *   const session = await sessionService.createSession(sessionData);
     *   // Additional operations...
     * });
     */
    async createSession(sessionData) {
        const functionName = 'createSession';

        try {
            // Validate session data
            if (!sessionData || typeof sessionData !== 'object') {
                throw new ValidationError({
                    message: 'Session data must be an object',
                    className: this.className,
                    functionName,
                    details: {
                        receivedType: typeof sessionData
                    }
                });
            }

            const { userId, deviceIp, userAgent } = sessionData;

            // Validate userId
            const userIdValidation = this.validator.validateUUID(userId, 'User ID');
            if (!userIdValidation.isValid) {
                throw new ValidationError({
                    message: userIdValidation.error,
                    className: this.className,
                    functionName,
                    details: {
                        field: 'userId',
                        received: userId,
                        receivedType: typeof userId
                    }
                });
            }

            // Validate deviceIp
            if (!deviceIp || typeof deviceIp !== 'string' || deviceIp.trim().length === 0) {
                throw new ValidationError({
                    message: 'Device IP is required and must be a non-empty string',
                    className: this.className,
                    functionName,
                    details: {
                        field: 'deviceIp',
                        receivedType: typeof deviceIp
                    }
                });
            }

            // Validate userAgent (optional but recommended)
            if (userAgent !== undefined && typeof userAgent !== 'string') {
                throw new ValidationError({
                    message: 'User agent must be a string',
                    className: this.className,
                    functionName,
                    details: {
                        field: 'userAgent',
                        receivedType: typeof userAgent
                    }
                });
            }

            // Generate session components
            const sessionId = this._generateSessionId();
            const token = this._generateJWTToken(userIdValidation.sanitized, sessionId);
            const cookieHash = this._generateCookieHash(sessionId, userIdValidation.sanitized);

            // Execute atomic transaction
            const newSession = await databaseInstance.transaction(async (client) => {
                // Initialize repositories with transaction client
                const sessionRepo = new UserSessionRepository(client);
                const activityRepo = new UserActivityRepository(client);

                // Step 1: Create session record
                const session = await sessionRepo.createSession(
                    userIdValidation.sanitized,
                    {
                        sessionId,
                        cookieHash,
                        ttl: this.SESSION_TTL,
                        deviceIp: deviceIp.trim(),
                        userAgent: userAgent || null
                    }
                );

                // Step 2: Update user activity to 'logged in'
                try {
                    await activityRepo.updateActivity(
                        userIdValidation.sanitized,
                        'logged in'
                    );
                } catch (error) {
                    throw new DatabaseError({
                        message: 'Failed to update user activity status',
                        className: this.className,
                        functionName,
                        cause: error,
                        details: {
                            userId: userIdValidation.sanitized,
                            step: 'activity_update'
                        }
                    });
                }

                return session;
            });

            // Return session data with token
            return {
                sessionId: newSession.session_id,
                token,
                cookieHash: newSession.cookie_hash,
                expiresAt: newSession.expires_at,
                userId: newSession.id
            };

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof DatabaseError ||
                error instanceof AuthenticationError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'Failed to create session',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    userId: sessionData?.userId?.toString().substring(0, 50)
                }
            });

            ErrorHandler.logError(serviceError);
            throw serviceError;
        }
    }

    /**
     * Updates session activity timestamp.
     * 
     * Extends session lifetime by updating last_used timestamp.
     * Typically called on each authenticated request to keep session active.
     * 
     * @async
     * @param {string} sessionId - Unique session identifier
     * 
     * @returns {Promise<Object>} Updated session record
     * @returns {string} return.sessionId - Session identifier
     * @returns {Date} return.lastUsed - Updated timestamp
     * @returns {Date} return.expiresAt - Session expiration
     * @returns {boolean} return.isActive - Session status
     * 
     * @throws {ValidationError} If sessionId is invalid
     * @throws {NotFoundError} If session doesn't exist
     * @throws {DatabaseError} If database operation fails
     * 
     * @example
     * // Update session on each request
     * app.use(async (req, res, next) => {
     *   if (req.sessionId) {
     *     await sessionService.updateSession(req.sessionId);
     *   }
     *   next();
     * });
     * 
     * @example
     * // Extend session with new TTL
     * await sessionService.updateSession(sessionId, {
     *   ttl: '48 hours'
     * });
     */
    async updateSession(sessionId, updateData = {}) {
        const functionName = 'updateSession';

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

            const sessionRepo = new UserSessionRepository();
            const updatedSession = await sessionRepo.updateSession(sessionId, updateData);

            return {
                sessionId: updatedSession.session_id,
                lastUsed: updatedSession.last_used,
                expiresAt: updatedSession.expires_at,
                isActive: updatedSession.is_active
            };

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof NotFoundError || 
                error instanceof DatabaseError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'Failed to update session',
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
     * Finds and validates a session.
     * 
     * Retrieves session by ID or by user ID + session ID combination.
     * Validates session is active and not expired.
     * 
     * @async
     * @param {Object} searchCriteria - Search parameters
     * @param {string} [searchCriteria.sessionId] - Session ID to search by
     * @param {string} [searchCriteria.userId] - User ID to search by (requires sessionId)
     * 
     * @returns {Promise<Object|null>} Session record if found and valid, null otherwise
     * @returns {string} return.sessionId - Session identifier
     * @returns {string} return.userId - User UUID
     * @returns {string} return.cookieHash - Cookie validation hash
     * @returns {Date} return.createdAt - Session creation timestamp
     * @returns {Date} return.expiresAt - Session expiration timestamp
     * @returns {Date} return.lastUsed - Last activity timestamp
     * @returns {boolean} return.isActive - Session status
     * @returns {string} return.deviceIp - Client IP address
     * @returns {string} return.userAgent - Client user agent
     * 
     * @throws {ValidationError} If search criteria is invalid
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * // Find by session ID only
     * const session = await sessionService.findSession({ 
     *   sessionId: 'session-uuid' 
     * });
     * 
     * @example
     * // Find by user ID and session ID (more secure)
     * const session = await sessionService.findSession({
     *   userId: '550e8400-e29b-41d4-a716-446655440000',
     *   sessionId: 'session-uuid'
     * });
     */
    async findSession(searchCriteria) {
        const functionName = 'findSession';

        try {
            // Validate search criteria
            if (!searchCriteria || typeof searchCriteria !== 'object') {
                throw new ValidationError({
                    message: 'Search criteria must be an object',
                    className: this.className,
                    functionName,
                    details: {
                        receivedType: typeof searchCriteria
                    }
                });
            }

            const { sessionId, userId } = searchCriteria;

            // Ensure at least sessionId is provided
            if (!sessionId) {
                throw new ValidationError({
                    message: 'Session ID is required',
                    className: this.className,
                    functionName,
                    details: {
                        hint: 'Provide sessionId to search'
                    }
                });
            }

            const sessionRepo = new UserSessionRepository();
            let session;

            // Search by both userId and sessionId (more secure)
            if (userId) {
                session = await sessionRepo.findSession(userId, sessionId);
            } else {
                // Search by sessionId only
                session = await sessionRepo.findSessionBySessionId(sessionId);
            }

            if (!session) {
                return null;
            }

            // Validate session is active and not expired
            const now = new Date();
            const isExpired = new Date(session.expires_at) < now;
            
            if (!session.is_active || isExpired) {
                return null;
            }

            return {
                sessionId: session.session_id,
                userId: session.id,
                cookieHash: session.cookie_hash,
                createdAt: session.created_at,
                expiresAt: session.expires_at,
                lastUsed: session.last_used,
                isActive: session.is_active,
                deviceIp: session.device_ip,
                userAgent: session.user_agent
            };

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof DatabaseError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'Failed to find session',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    searchCriteria: Object.keys(searchCriteria || {})
                }
            });

            ErrorHandler.logError(serviceError);
            throw serviceError;
        }
    }

    /**
     * Validates a session with JWT token verification.
     * 
     * Performs comprehensive session validation:
     * 1. Verifies JWT token signature and expiration
     * 2. Checks session exists in database
     * 3. Validates session is active and not expired
     * 4. Validates cookie hash matches
     * 5. Updates last_used timestamp
     * 
     * @async
     * @param {string} sessionId - Unique session identifier
     * @param {string} token - JWT token to verify
     * @param {string} [cookieHash] - Cookie hash for validation (optional)
     * 
     * @returns {Promise<Object>} Validated session with user info
     * @returns {boolean} return.valid - Whether session is valid
     * @returns {string} return.userId - User UUID
     * @returns {string} return.sessionId - Session identifier
     * 
     * @throws {ValidationError} If inputs are invalid
     * @throws {AuthenticationError} If token or session is invalid
     * @throws {DatabaseError} If database operation fails
     * 
     * @example
     * // Validate session in middleware
     * const validation = await sessionService.validateSession(
     *   req.cookies.sessionId,
     *   req.headers.authorization?.replace('Bearer ', '')
     * );
     * 
     * if (!validation.valid) {
     *   return res.status(401).json({ error: 'Invalid session' });
     * }
     * 
     * req.userId = validation.userId;
     */
    async validateSession(sessionId, token, cookieHash = null) {
        const functionName = 'validateSession';

        try {
            // Validate inputs
            if (!sessionId || typeof sessionId !== 'string') {
                throw new ValidationError({
                    message: 'Session ID is required and must be a string',
                    className: this.className,
                    functionName,
                    details: {
                        field: 'sessionId'
                    }
                });
            }

            if (!token || typeof token !== 'string') {
                throw new ValidationError({
                    message: 'Token is required and must be a string',
                    className: this.className,
                    functionName,
                    details: {
                        field: 'token'
                    }
                });
            }

            // Step 1: Verify JWT token
            const decoded = this._verifyJWTToken(token);

            // Validate sessionId matches token
            if (decoded.sessionId !== sessionId) {
                throw new AuthenticationError({
                    message: 'Session ID mismatch',
                    className: this.className,
                    functionName,
                    details: {
                        hint: 'Token sessionId does not match provided sessionId'
                    }
                });
            }

            // Step 2: Find session in database
            const session = await this.findSession({ 
                sessionId, 
                userId: decoded.userId 
            });

            if (!session) {
                throw new AuthenticationError({
                    message: 'Session not found or expired',
                    className: this.className,
                    functionName
                });
            }

            // Step 3: Validate cookie hash if provided
            if (cookieHash) {
                const expectedHash = this._generateCookieHash(sessionId, decoded.userId);
                
                if (cookieHash !== expectedHash) {
                    throw new AuthenticationError({
                        message: 'Invalid cookie hash',
                        className: this.className,
                        functionName,
                        details: {
                            hint: 'Cookie may have been tampered with'
                        }
                    });
                }
            }

            // Step 4: Update session activity
            await this.updateSession(sessionId);

            return {
                valid: true,
                userId: decoded.userId,
                sessionId: decoded.sessionId
            };

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof AuthenticationError || 
                error instanceof DatabaseError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'Session validation failed',
                className: this.className,
                functionName,
                cause: error
            });

            ErrorHandler.logError(serviceError);
            throw serviceError;
        }
    }

    /**
     * Deletes a session (logout).
     * 
     * Performs atomic transaction to:
     * 1. Delete session from database
     * 2. Update user activity if no other active sessions exist
     * 
     * @async
     * @param {string} sessionId - Unique session identifier
     * @param {string} [userId] - User UUID (optional, for validation)
     * 
     * @returns {Promise<boolean>} True if deleted successfully
     * 
     * @throws {ValidationError} If sessionId is invalid
     * @throws {DatabaseError} If database operation fails
     * 
     * @example
     * // Logout current device
     * await sessionService.deleteSession(req.sessionId);
     * res.clearCookie('sessionId');
     * res.json({ message: 'Logged out successfully' });
     * 
     * @example
     * // Logout with user validation
     * await sessionService.deleteSession(sessionId, userId);
     */
    async deleteSession(sessionId, userId = null) {
        const functionName = 'deleteSession';

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

            // Execute atomic transaction
            await databaseInstance.transaction(async (client) => {
                const sessionRepo = new UserSessionRepository(client);
                const activityRepo = new UserActivityRepository(client);

                // Get session details before deletion if userId not provided
                let sessionUserId = userId;
                if (!sessionUserId) {
                    const session = await sessionRepo.findSessionBySessionId(sessionId);
                    if (session) {
                        sessionUserId = session.id;
                    }
                }

                // Step 1: Delete session
                const deleted = await sessionRepo.deleteSessionBySessionId(sessionId);

                if (!deleted) {
                    throw new NotFoundError({
                        message: 'Session not found',
                        className: this.className,
                        functionName,
                        details: {
                            sessionId: sessionId.substring(0, 50)
                        }
                    });
                }

                // Step 2: Update user activity if no other active sessions
                if (sessionUserId) {
                    const activeSessions = await sessionRepo.getActiveSessions(sessionUserId);
                    
                    // If no active sessions remaining, update status to 'logged out'
                    if (activeSessions.length === 0) {
                        try {
                            await activityRepo.updateActivity(sessionUserId, 'logged out');
                        } catch (error) {
                            // Log error but don't fail session deletion
                            ErrorHandler.logError(new DatabaseError({
                                message: 'Failed to update activity status during logout',
                                className: this.className,
                                functionName,
                                cause: error,
                                details: {
                                    userId: sessionUserId
                                }
                            }));
                        }
                    }
                }
            });

            return true;

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof NotFoundError || 
                error instanceof DatabaseError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'Failed to delete session',
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
     * Deletes all sessions for a user (logout all devices).
     * 
     * @async
     * @param {string} userId - UUID of the user
     * 
     * @returns {Promise<number>} Number of sessions deleted
     * 
     * @throws {ValidationError} If userId is invalid
     * @throws {DatabaseError} If database operation fails
     * 
     * @example
     * // Logout all devices
     * const count = await sessionService.deleteAllUserSessions(userId);
     * console.log(`Logged out from ${count} devices`);
     */
    async deleteAllUserSessions(userId) {
        const functionName = 'deleteAllUserSessions';

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

            // Execute atomic transaction
            const deletedCount = await databaseInstance.transaction(async (client) => {
                const sessionRepo = new UserSessionRepository(client);
                const activityRepo = new UserActivityRepository(client);

                // Delete all sessions
                const count = await sessionRepo.deleteSessionByUserId(validation.sanitized);

                // Update activity to 'logged out'
                try {
                    await activityRepo.updateActivity(validation.sanitized, 'logged out');
                } catch (error) {
                    ErrorHandler.logError(new DatabaseError({
                        message: 'Failed to update activity status during logout all',
                        className: this.className,
                        functionName,
                        cause: error,
                        details: {
                            userId: validation.sanitized
                        }
                    }));
                }

                return count;
            });

            return deletedCount;

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof DatabaseError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'Failed to delete all user sessions',
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
     * Gets all active sessions for a user.
     * 
     * @async
     * @param {string} userId - UUID of the user
     * 
     * @returns {Promise<Array>} Array of active sessions
     * 
     * @throws {ValidationError} If userId is invalid
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * const sessions = await sessionService.getActiveSessions(userId);
     * console.log(`User has ${sessions.length} active devices`);
     */
    async getActiveSessions(userId) {
        const functionName = 'getActiveSessions';

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

            const sessionRepo = new UserSessionRepository();
            const sessions = await sessionRepo.getActiveSessions(validation.sanitized);

            return sessions.map(session => ({
                sessionId: session.session_id,
                deviceIp: session.device_ip,
                userAgent: session.user_agent,
                createdAt: session.created_at,
                lastUsed: session.last_used,
                expiresAt: session.expires_at
            }));

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof DatabaseError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'Failed to get active sessions',
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

export default SessionManagementService;
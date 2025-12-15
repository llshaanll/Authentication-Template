/**
 * @fileoverview User Session Repository
 * 
 * Handles all database operations related to user session management.
 * Implements the Repository Pattern to abstract session data access logic
 * from business logic, enabling secure session storage, retrieval, and lifecycle management.
 * 
 * SOLID Principles Applied:
 * - Single Responsibility: Only handles session data persistence
 * - Open/Closed: Extendable for session policies without modification
 * - Liskov Substitution: Can be replaced with any ISessionRepository implementation
 * - Interface Segregation: Focused interface for session operations only
 * - Dependency Inversion: Depends on database abstraction, not concrete implementation
 * 
 * Security Features:
 * - Session ID uniqueness enforcement
 * - Cookie hash storage for validation
 * - Device tracking (IP, User Agent)
 * - Session expiration management
 * - Active/inactive session status
 * - Last used timestamp tracking
 * 
 * @module repositories/user/UserSessionRepository
 * @requires config/database
 * @requires utilities/loggers/error.logger
 * @requires utilities/loggers/errorHandler.logger
 * @requires validators/SecurityValidator
 * 
 * @author mr.shaan
 * @version 1.0.0
 * @since 2025-12-15
 */

import databaseInstance from '../../configuration/postgres/database.config.js';
import { 
    ValidationError, 
    DatabaseError, 
    NotFoundError, 
    ConflictError 
} from '../../utilities/loggers/error.logger.js';
import ErrorHandler from '../../utilities/loggers/errorHandler.logger.js';
import SecurityValidator from '../../utilities/validators/security.validator.js';

/**
 * Repository class for User Session data access.
 * 
 * Manages session records with:
 * - Unique session ID generation and validation
 * - Cookie hash storage for session verification
 * - Device fingerprinting (IP, User Agent)
 * - TTL-based session expiration
 * - Active session tracking
 * - Multi-device session support
 * 
 * Database Schema:
 * - id (UUID): References users(id)
 * - session_id (VARCHAR): Unique session identifier
 * - cookie_hash (VARCHAR): Hashed session cookie for validation
 * - ttl (VARCHAR): Time-to-live duration (e.g., '24 hours')
 * - device_ip (INET): Client IP address
 * - user_agent (TEXT): Client user agent string
 * - created_at (TIMESTAMP): Session creation timestamp
 * - expires_at (TIMESTAMP): Session expiration timestamp
 * - last_used (TIMESTAMP): Last activity timestamp
 * - is_active (BOOLEAN): Active/inactive status
 * 
 * @class UserSessionRepository
 * 
 * @example
 * // Initialize repository
 * const sessionRepo = new UserSessionRepository();
 * 
 * // Create session
 * const session = await sessionRepo.createSession(userId, {
 *   sessionId: 'unique-session-id',
 *   cookieHash: 'hashed-cookie-value',
 *   ttl: '24 hours',
 *   deviceIp: '192.168.1.1',
 *   userAgent: 'Mozilla/5.0...'
 * });
 */
class UserSessionRepository {
    /**
     * Creates a new UserSessionRepository instance.
     * 
     * Implements Dependency Injection pattern for database connection,
     * allowing the repository to work with either:
     * - Connection pool (default) for standalone operations
     * - Transaction client for atomic multi-step operations
     * 
     * @constructor
     * @param {pg.PoolClient|null} [dbClient=null] - Optional database client for transactions
     * 
     * @example
     * // Standalone usage (uses connection pool)
     * const sessionRepo = new UserSessionRepository();
     * 
     * @example
     * // Transaction usage (uses dedicated client)
     * await databaseInstance.transaction(async (client) => {
     *   const sessionRepo = new UserSessionRepository(client);
     *   await sessionRepo.createSession(userId, sessionData);
     * });
     */
    constructor(dbClient = null) {
        /**
         * Database connection instance.
         * Either a transaction client or the connection pool.
         * 
         * @private
         * @type {pg.PoolClient|Database}
         */
        this.db = dbClient || databaseInstance;

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
        this.className = 'UserSessionRepository';
    }

    /**
     * Validates session data object structure and content.
     * 
     * @private
     * @param {Object} sessionData - Session data to validate
     * @param {string} functionName - Calling function name for error context
     * @throws {ValidationError} If sessionData is invalid
     */
    _validateSessionData(sessionData, functionName) {
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

        const { sessionId, cookieHash, ttl, deviceIp, userAgent } = sessionData;

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

        if (sessionId.length > 255) {
            throw new ValidationError({
                message: 'Session ID must not exceed 255 characters',
                className: this.className,
                functionName,
                details: {
                    field: 'sessionId',
                    receivedLength: sessionId.length,
                    maxLength: 255
                }
            });
        }

        // Validate cookieHash
        if (!cookieHash || typeof cookieHash !== 'string' || cookieHash.trim().length === 0) {
            throw new ValidationError({
                message: 'Cookie hash is required and must be a non-empty string',
                className: this.className,
                functionName,
                details: {
                    field: 'cookieHash',
                    receivedType: typeof cookieHash
                }
            });
        }

        if (cookieHash.length > 255) {
            throw new ValidationError({
                message: 'Cookie hash must not exceed 255 characters',
                className: this.className,
                functionName,
                details: {
                    field: 'cookieHash',
                    receivedLength: cookieHash.length,
                    maxLength: 255
                }
            });
        }

        // Validate ttl
        if (!ttl || typeof ttl !== 'string' || ttl.trim().length === 0) {
            throw new ValidationError({
                message: 'TTL is required and must be a non-empty string',
                className: this.className,
                functionName,
                details: {
                    field: 'ttl',
                    receivedType: typeof ttl,
                    hint: 'Use PostgreSQL interval format (e.g., "24 hours", "7 days")'
                }
            });
        }

        // Validate deviceIp (basic IPv4/IPv6 format)
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

        // Basic IP validation (IPv4 or IPv6)
        const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6Pattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        
        if (!ipv4Pattern.test(deviceIp) && !ipv6Pattern.test(deviceIp)) {
            throw new ValidationError({
                message: 'Invalid IP address format',
                className: this.className,
                functionName,
                details: {
                    field: 'deviceIp',
                    receivedValue: deviceIp.substring(0, 50),
                    hint: 'Must be valid IPv4 or IPv6 address'
                }
            });
        }

        // Validate userAgent (optional but if provided must be string)
        if (userAgent !== undefined && userAgent !== null) {
            if (typeof userAgent !== 'string') {
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
        }
    }

    /**
     * Calculates session expiration timestamp based on TTL.
     * 
     * @private
     * @param {string} ttl - Time-to-live string (PostgreSQL interval format)
     * @returns {string} SQL expression for expiration calculation
     * 
     * @example
     * this._calculateExpiration('24 hours');
     * // Returns: "NOW() + INTERVAL '24 hours'"
     */
    _calculateExpiration(ttl) {
        return `NOW() + INTERVAL '${ttl}'`;
    }

    /**
     * Creates a new session record for a user.
     * 
     * Establishes a new authenticated session with:
     * - Unique session identifier
     * - Hashed cookie for validation
     * - Device fingerprinting
     * - Automatic expiration calculation
     * - Active status initialization
     * 
     * @async
     * @param {string} userId - UUID of the user (must exist in users table)
     * @param {Object} sessionData - Session configuration data
     * @param {string} sessionData.sessionId - Unique session identifier (max 255 chars)
     * @param {string} sessionData.cookieHash - Hashed session cookie (max 255 chars)
     * @param {string} sessionData.ttl - Session duration (e.g., '24 hours', '7 days')
     * @param {string} sessionData.deviceIp - Client IP address (IPv4 or IPv6)
     * @param {string} [sessionData.userAgent] - Client user agent string (optional)
     * 
     * @returns {Promise<Object>} Created session record
     * @returns {string} return.id - User UUID
     * @returns {string} return.session_id - Unique session identifier
     * @returns {string} return.cookie_hash - Hashed cookie value
     * @returns {string} return.ttl - Time-to-live duration
     * @returns {string} return.device_ip - Client IP address
     * @returns {string} return.user_agent - Client user agent
     * @returns {Date} return.created_at - Session creation timestamp
     * @returns {Date} return.expires_at - Session expiration timestamp
     * @returns {Date} return.last_used - Last activity timestamp
     * @returns {boolean} return.is_active - Session status (true)
     * 
     * @throws {ValidationError} If userId or sessionData is invalid
     * @throws {ConflictError} If session_id already exists
     * @throws {DatabaseError} If user doesn't exist or database operation fails
     * 
     * @example
     * const session = await sessionRepo.createSession(
     *   '550e8400-e29b-41d4-a716-446655440000',
     *   {
     *     sessionId: crypto.randomUUID(),
     *     cookieHash: await hashCookie(cookieValue),
     *     ttl: '24 hours',
     *     deviceIp: req.ip,
     *     userAgent: req.headers['user-agent']
     *   }
     * );
     * 
     * @example
     * // Create session within login transaction
     * await databaseInstance.transaction(async (client) => {
     *   const sessionRepo = new UserSessionRepository(client);
     *   const activityRepo = new UserActivityRepository(client);
     *   
     *   const session = await sessionRepo.createSession(userId, sessionData);
     *   await activityRepo.updateLoginStatus(userId, 'logged in');
     * });
     */
    async createSession(userId, sessionData) {
        const functionName = 'createSession';

        try {
            // Validate userId (UUID format)
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

            // Validate session data
            this._validateSessionData(sessionData, functionName);

            const { sessionId, cookieHash, ttl, deviceIp, userAgent } = sessionData;

            // Sanitize inputs
            const sanitizedSessionId = this.validator.sanitizeString(sessionId);
            const sanitizedCookieHash = this.validator.sanitizeString(cookieHash);
            const sanitizedTtl = this.validator.sanitizeString(ttl);
            const sanitizedDeviceIp = deviceIp.trim();
            const sanitizedUserAgent = userAgent ? this.validator.sanitizeString(userAgent) : null;

            const query = `
                INSERT INTO user_sessions (
                    id, 
                    session_id, 
                    cookie_hash, 
                    ttl, 
                    device_ip, 
                    user_agent,
                    expires_at,
                    is_active
                )
                VALUES ($1, $2, $3, $4, $5, $6, ${this._calculateExpiration(sanitizedTtl)}, true)
                RETURNING 
                    id, 
                    session_id, 
                    cookie_hash, 
                    ttl, 
                    device_ip, 
                    user_agent,
                    created_at, 
                    expires_at, 
                    last_used, 
                    is_active
            `;

            const result = await this.db.query(query, [
                userIdValidation.sanitized,
                sanitizedSessionId,
                sanitizedCookieHash,
                sanitizedTtl,
                sanitizedDeviceIp,
                sanitizedUserAgent
            ]);

            if (!result.rows || result.rows.length === 0) {
                throw new DatabaseError({
                    message: 'Session creation failed - no data returned',
                    className: this.className,
                    functionName,
                    details: {
                        userId: userIdValidation.sanitized
                    }
                });
            }

            return result.rows[0];

        } catch (error) {
            // Handle duplicate session_id (unique constraint violation)
            if (error.code === '23505' && error.constraint === 'user_sessions_session_id_key') {
                const conflictError = new ConflictError({
                    message: 'Session ID already exists',
                    className: this.className,
                    functionName,
                    cause: error,
                    details: {
                        sessionId: sessionData?.sessionId?.substring(0, 50),
                        constraint: error.constraint,
                        hint: 'Generate a new unique session ID'
                    }
                });
                
                ErrorHandler.logError(conflictError);
                throw conflictError;
            }

            // Handle foreign key constraint (user doesn't exist)
            if (error.code === '23503') {
                const dbError = new DatabaseError({
                    message: 'User does not exist',
                    className: this.className,
                    functionName,
                    cause: error,
                    details: {
                        userId: userId?.toString().substring(0, 50),
                        constraint: error.constraint,
                        hint: 'Ensure user exists before creating session'
                    }
                });
                
                ErrorHandler.logError(dbError);
                throw dbError;
            }

            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof ConflictError) {
                throw error;
            }

            // Wrap unexpected errors
            const dbError = new DatabaseError({
                message: 'Failed to create session',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    userId: userId?.toString().substring(0, 50),
                    sessionId: sessionData?.sessionId?.substring(0, 50),
                    errorCode: error.code
                }
            });

            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }

    /**
     * Updates session information.
     * 
     * Supports updating:
     * - cookie_hash: New hashed cookie value
     * - last_used: Activity timestamp (auto-updated)
     * - is_active: Session status
     * - expires_at: New expiration time
     * 
     * Partial updates supported - only provided fields are updated.
     * 
     * @async
     * @param {string} sessionId - Unique session identifier
     * @param {Object} updateData - Fields to update
     * @param {string} [updateData.cookieHash] - New cookie hash
     * @param {boolean} [updateData.isActive] - New active status
     * @param {string} [updateData.ttl] - New TTL (recalculates expires_at)
     * 
     * @returns {Promise<Object>} Updated session record
     * 
     * @throws {ValidationError} If sessionId or updateData is invalid
     * @throws {NotFoundError} If session doesn't exist
     * @throws {DatabaseError} If database operation fails
     * 
     * @example
     * // Update last used timestamp (touch session)
     * await sessionRepo.updateSession(sessionId, {});
     * 
     * @example
     * // Deactivate session (logout)
     * await sessionRepo.updateSession(sessionId, {
     *   isActive: false
     * });
     * 
     * @example
     * // Extend session TTL
     * await sessionRepo.updateSession(sessionId, {
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

            const sanitizedSessionId = this.validator.sanitizeString(sessionId);

            // Validate updateData
            if (!updateData || typeof updateData !== 'object') {
                throw new ValidationError({
                    message: 'Update data must be an object',
                    className: this.className,
                    functionName,
                    details: {
                        receivedType: typeof updateData
                    }
                });
            }

            // Build dynamic UPDATE query
            const fields = ['last_used = NOW()']; // Always update last_used
            const values = [];
            let paramIndex = 1;

            // Update cookieHash if provided
            if (updateData.cookieHash !== undefined) {
                if (typeof updateData.cookieHash !== 'string' || updateData.cookieHash.trim().length === 0) {
                    throw new ValidationError({
                        message: 'Cookie hash must be a non-empty string',
                        className: this.className,
                        functionName,
                        details: {
                            field: 'cookieHash',
                            receivedType: typeof updateData.cookieHash
                        }
                    });
                }

                fields.push(`cookie_hash = $${paramIndex}`);
                values.push(this.validator.sanitizeString(updateData.cookieHash));
                paramIndex++;
            }

            // Update isActive if provided
            if (updateData.isActive !== undefined) {
                if (typeof updateData.isActive !== 'boolean') {
                    throw new ValidationError({
                        message: 'isActive must be a boolean',
                        className: this.className,
                        functionName,
                        details: {
                            field: 'isActive',
                            receivedType: typeof updateData.isActive
                        }
                    });
                }

                fields.push(`is_active = $${paramIndex}`);
                values.push(updateData.isActive);
                paramIndex++;
            }

            // Update expires_at if TTL is provided
            if (updateData.ttl !== undefined) {
                if (typeof updateData.ttl !== 'string' || updateData.ttl.trim().length === 0) {
                    throw new ValidationError({
                        message: 'TTL must be a non-empty string',
                        className: this.className,
                        functionName,
                        details: {
                            field: 'ttl',
                            receivedType: typeof updateData.ttl
                        }
                    });
                }

                const sanitizedTtl = this.validator.sanitizeString(updateData.ttl);
                fields.push(`ttl = $${paramIndex}`);
                values.push(sanitizedTtl);
                paramIndex++;

                fields.push(`expires_at = ${this._calculateExpiration(sanitizedTtl)}`);
            }

            // Add sessionId as final parameter
            values.push(sanitizedSessionId);

            const query = `
                UPDATE user_sessions
                SET ${fields.join(', ')}
                WHERE session_id = $${paramIndex}
                RETURNING 
                    id, 
                    session_id, 
                    cookie_hash, 
                    ttl, 
                    device_ip, 
                    user_agent,
                    created_at, 
                    expires_at, 
                    last_used, 
                    is_active
            `;

            const result = await this.db.query(query, values);

            if (!result.rows || result.rows.length === 0) {
                throw new NotFoundError({
                    message: 'Session not found',
                    className: this.className,
                    functionName,
                    details: {
                        sessionId: sanitizedSessionId.substring(0, 50)
                    }
                });
            }

            return result.rows[0];

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof NotFoundError) {
                throw error;
            }

            // Wrap unexpected errors
            const dbError = new DatabaseError({
                message: 'Failed to update session',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    sessionId: sessionId?.substring(0, 50),
                    updateFields: Object.keys(updateData || {}),
                    errorCode: error.code
                }
            });

            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }

    /**
     * Finds session by user ID and session ID.
     * 
     * Retrieves session record matching both user ID and session ID.
     * Useful for validating session ownership.
     * 
     * @async
     * @param {string} userId - UUID of the user
     * @param {string} sessionId - Unique session identifier
     * 
     * @returns {Promise<Object|null>} Session record if found, null otherwise
     * 
     * @throws {ValidationError} If userId or sessionId is invalid
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * const session = await sessionRepo.findSession(userId, sessionId);
     * if (session && session.is_active && new Date() < session.expires_at) {
     *   // Session is valid
     * }
     */
    async findSession(userId, sessionId) {
        const functionName = 'findSession';

        try {
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

            const sanitizedSessionId = this.validator.sanitizeString(sessionId);

            const query = `
                SELECT 
                    id, 
                    session_id, 
                    cookie_hash, 
                    ttl, 
                    device_ip, 
                    user_agent,
                    created_at, 
                    expires_at, 
                    last_used, 
                    is_active
                FROM user_sessions
                WHERE id = $1 AND session_id = $2
            `;

            const result = await this.db.query(query, [
                userIdValidation.sanitized,
                sanitizedSessionId
            ]);

            return result.rows.length > 0 ? result.rows[0] : null;

        } catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to find session',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    userId: userId?.toString().substring(0, 50),
                    sessionId: sessionId?.substring(0, 50),
                    errorCode: error.code
                }
            });

            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }

    /**
     * Finds session by session ID only.
     * 
     * @async
     * @param {string} sessionId - Unique session identifier
     * 
     * @returns {Promise<Object|null>} Session record if found, null otherwise
     * 
     * @throws {ValidationError} If sessionId is invalid
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * const session = await sessionRepo.findSessionBySessionId(sessionId);
     */
    async findSessionBySessionId(sessionId) {
        const functionName = 'findSessionBySessionId';

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

            const sanitizedSessionId = this.validator.sanitizeString(sessionId);

            const query = `
                SELECT 
                    id, 
                    session_id, 
                    cookie_hash, 
                    ttl, 
                    device_ip, 
                    user_agent,
                    created_at, 
                    expires_at, 
                    last_used, 
                    is_active
                FROM user_sessions
                WHERE session_id = $1
            `;

            const result = await this.db.query(query, [sanitizedSessionId]);

            return result.rows.length > 0 ? result.rows[0] : null;

        } catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to find session by session ID',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    sessionId: sessionId?.substring(0, 50),
                    errorCode: error.code
                }
            });

            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }

    /**
     * Deletes session by user ID.
     * 
     * Deletes ALL sessions for a specific user.
     * Use for logout all devices or account deletion.
     * 
     * @async
     * @param {string} userId - UUID of the user
     * 
     * @returns {Promise<number>} Number of sessions deleted
     * 
     * @throws {ValidationError} If userId is not a valid UUID
     * @throws {DatabaseError} If database operation fails
     * 
     * @example
     * // Logout all devices
     * const deletedCount = await sessionRepo.deleteSessionByUserId(userId);
     * console.log(`Deleted ${deletedCount} sessions`);
     */
    async deleteSessionByUserId(userId) {
        const functionName = 'deleteSessionByUserId';

        try {
            // Validate UUID format
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

            const query = `
                DELETE FROM user_sessions
                WHERE id = $1
            `;

            const result = await this.db.query(query, [validation.sanitized]);

            return result.rowCount || 0;

        } catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to delete sessions by user ID',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    userId: userId?.toString().substring(0, 50),
                    errorCode: error.code
                }
            });

            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }

    /**
     * Deletes session by session ID.
     * 
     * Deletes a specific session. Use for single device logout.
     * 
     * @async
     * @param {string} sessionId - Unique session identifier
     * 
     * @returns {Promise<boolean>} True if deleted, false if not found
     * 
     * @throws {ValidationError} If sessionId is invalid
     * @throws {DatabaseError} If database operation fails
     * 
     * @example
     * // Logout current device
     * const deleted = await sessionRepo.deleteSessionBySessionId(sessionId);
     * if (deleted) {
     *   console.log('Session terminated');
     * }
     */
    async deleteSessionBySessionId(sessionId) {
        const functionName = 'deleteSessionBySessionId';

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

            const sanitizedSessionId = this.validator.sanitizeString(sessionId);

            const query = `
                DELETE FROM user_sessions
                WHERE session_id = $1
            `;

            const result = await this.db.query(query, [sanitizedSessionId]);

            return result.rowCount > 0;

        } catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to delete session by session ID',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    sessionId: sessionId?.substring(0, 50),
                    errorCode: error.code
                }
            });

            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }

    /**
     * Gets all active sessions for a user.
     * 
     * @async
     * @param {string} userId - UUID of the user
     * 
     * @returns {Promise<Array>} Array of active session records
     * 
     * @throws {ValidationError} If userId is not a valid UUID
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * const activeSessions = await sessionRepo.getActiveSessions(userId);
     * console.log(`User has ${activeSessions.length} active sessions`);
     */
    async getActiveSessions(userId) {
        const functionName = 'getActiveSessions';

        try {
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

            const query = `
                SELECT 
                    id, 
                    session_id, 
                    cookie_hash, 
                    ttl, 
                    device_ip, 
                    user_agent,
                    created_at, 
                    expires_at, 
                    last_used, 
                    is_active
                FROM user_sessions
                WHERE id = $1 
                  AND is_active = true 
                  AND expires_at > NOW()
                ORDER BY last_used DESC
            `;

            const result = await this.db.query(query, [validation.sanitized]);

            return result.rows || [];

        } catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to get active sessions',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    userId: userId?.toString().substring(0, 50),
                    errorCode: error.code
                }
            });

            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }

    /**
     * Deletes expired sessions (cleanup utility).
     * 
     * @async
     * @returns {Promise<number>} Number of expired sessions deleted
     * 
     * @throws {DatabaseError} If database operation fails
     * 
     * @example
     * // Run as scheduled job
     * const cleaned = await sessionRepo.deleteExpiredSessions();
     * console.log(`Cleaned ${cleaned} expired sessions`);
     */
    async deleteExpiredSessions() {
        const functionName = 'deleteExpiredSessions';

        try {
            const query = `
                DELETE FROM user_sessions
                WHERE expires_at < NOW()
            `;

            const result = await this.db.query(query);

            return result.rowCount || 0;

        } catch (error) {
            const dbError = new DatabaseError({
                message: 'Failed to delete expired sessions',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    errorCode: error.code
                }
            });

            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }
}

export default UserSessionRepository;
/**
 * @fileoverview User Activity Repository
 * 
 * Handles all database operations related to user activity tracking.
 * Implements the Repository Pattern to abstract activity data access logic
 * from business logic, enabling activity monitoring, status management, and analytics.
 * 
 * SOLID Principles Applied:
 * - Single Responsibility: Only handles activity data persistence
 * - Open/Closed: Extendable for activity analytics without modification
 * - Liskov Substitution: Can be replaced with any IActivityRepository implementation
 * - Interface Segregation: Focused interface for activity operations only
 * - Dependency Inversion: Depends on database abstraction, not concrete implementation
 * 
 * Activity Tracking Features:
 * - User login/logout status tracking
 * - Last seen timestamp management
 * - Login count analytics
 * - Active user querying by status
 * - Activity history maintenance
 * 
 * @module repositories/user/UserActivityRepository
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
 * Repository class for User Activity data access.
 * 
 * Manages activity records with:
 * - User activity status tracking (logged in, logged out, inactive)
 * - Last seen timestamp updates
 * - Login count incrementation
 * - Active user filtering
 * - One-to-one relationship with users table
 * 
 * Database Schema:
 * - id (UUID): References users(id)
 * - active_status (VARCHAR): Current activity status
 *   Valid values: 'logged out', 'logged in', 'inactive'
 * - last_seen (TIMESTAMP): Last activity timestamp
 * - login_count (INTEGER): Total number of logins
 * - created_at (TIMESTAMP): Record creation timestamp
 * - updated_at (TIMESTAMP): Last update timestamp
 * 
 * @class UserActivityRepository
 * 
 * @example
 * // Initialize repository
 * const activityRepo = new UserActivityRepository();
 * 
 * // Create activity record
 * await activityRepo.createActivity(userId, 'logged out');
 * 
 * @example
 * // Use with transaction
 * await databaseInstance.transaction(async (client) => {
 *   const activityRepo = new UserActivityRepository(client);
 *   await activityRepo.createActivity(userId, 'logged in');
 * });
 */
class UserActivityRepository {
    /**
     * Creates a new UserActivityRepository instance.
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
     * const activityRepo = new UserActivityRepository();
     * 
     * @example
     * // Transaction usage (uses dedicated client)
     * await databaseInstance.transaction(async (client) => {
     *   const activityRepo = new UserActivityRepository(client);
     *   await activityRepo.createActivity(userId, 'logged in');
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
        this.className = 'UserActivityRepository';

        /**
         * Valid activity status values.
         * Defined by database CHECK constraint.
         * 
         * @private
         * @type {Array<string>}
         */
        this.VALID_STATUSES = ['logged out', 'logged in', 'inactive'];
    }

    /**
     * Validates activity status value.
     * 
     * @private
     * @param {string} activeStatus - Status to validate
     * @param {string} functionName - Calling function name for error context
     * @throws {ValidationError} If activeStatus is invalid
     */
    _validateActivityStatus(activeStatus, functionName) {
        if (!activeStatus || typeof activeStatus !== 'string') {
            throw new ValidationError({
                message: 'Active status must be a non-empty string',
                className: this.className,
                functionName,
                details: {
                    field: 'activeStatus',
                    receivedType: typeof activeStatus,
                    validValues: this.VALID_STATUSES
                }
            });
        }

        const sanitizedStatus = activeStatus.trim().toLowerCase();

        if (!this.VALID_STATUSES.includes(sanitizedStatus)) {
            throw new ValidationError({
                message: 'Invalid activity status value',
                className: this.className,
                functionName,
                details: {
                    field: 'activeStatus',
                    receivedValue: activeStatus,
                    validValues: this.VALID_STATUSES,
                    hint: 'Status must be one of: logged out, logged in, inactive'
                }
            });
        }

        return sanitizedStatus;
    }

    /**
     * Creates a new activity record for a user.
     * 
     * Initializes activity tracking for a user account. This should be called
     * during user registration to establish the activity baseline.
     * 
     * Initial State:
     * - active_status: Provided status (typically 'logged out' for new users)
     * - last_seen: Current timestamp
     * - login_count: 0 (initial state)
     * - created_at: Current timestamp
     * - updated_at: Current timestamp
     * 
     * @async
     * @param {string} userId - UUID of the user (must exist in users table)
     * @param {string} [activeStatus='logged out'] - Initial activity status
     *        Valid values: 'logged out', 'logged in', 'inactive'
     * 
     * @returns {Promise<Object>} Created activity record
     * @returns {string} return.id - User UUID (references users.id)
     * @returns {string} return.active_status - Current activity status
     * @returns {Date} return.last_seen - Last activity timestamp
     * @returns {number} return.login_count - Number of logins (0 initially)
     * @returns {Date} return.created_at - Record creation timestamp
     * @returns {Date} return.updated_at - Last update timestamp
     * 
     * @throws {ValidationError} If userId or activeStatus is invalid
     * @throws {ConflictError} If activity record already exists for user
     * @throws {DatabaseError} If user doesn't exist or database operation fails
     * 
     * @example
     * // Create activity during user registration
     * const activity = await activityRepo.createActivity(
     *   '550e8400-e29b-41d4-a716-446655440000',
     *   'logged out'
     * );
     * 
     * @example
     * // Within transaction (user creation + activity)
     * await databaseInstance.transaction(async (client) => {
     *   const userRepo = new UserInformationRepository(client);
     *   const activityRepo = new UserActivityRepository(client);
     *   
     *   const user = await userRepo.createUser(userData);
     *   await activityRepo.createActivity(user.id, 'logged out');
     * });
     */
    async createActivity(userId, activeStatus = 'logged out') {
        const functionName = 'createActivity';

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

            // Validate and sanitize activeStatus
            const sanitizedStatus = this._validateActivityStatus(activeStatus, functionName);

            const query = `
                INSERT INTO user_activity (id, active_status, login_count)
                VALUES ($1, $2, 0)
                RETURNING id, active_status, last_seen, login_count, created_at, updated_at
            `;

            const result = await this.db.query(query, [
                userIdValidation.sanitized,
                sanitizedStatus
            ]);

            if (!result.rows || result.rows.length === 0) {
                throw new DatabaseError({
                    message: 'Activity creation failed - no data returned',
                    className: this.className,
                    functionName,
                    details: {
                        userId: userIdValidation.sanitized
                    }
                });
            }

            return result.rows[0];

        } catch (error) {
            // Handle duplicate activity record (user already has activity)
            if (error.code === '23505') {
                const conflictError = new ConflictError({
                    message: 'Activity record already exists for this user',
                    className: this.className,
                    functionName,
                    cause: error,
                    details: {
                        userId: userId?.toString().substring(0, 50),
                        constraint: error.constraint,
                        hint: 'Use updateActivity() to change existing activity status'
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
                        hint: 'Create user record before creating activity'
                    }
                });
                
                ErrorHandler.logError(dbError);
                throw dbError;
            }

            // Handle invalid status (CHECK constraint violation)
            if (error.code === '23514') {
                const validationError = new ValidationError({
                    message: 'Invalid activity status value',
                    className: this.className,
                    functionName,
                    cause: error,
                    details: {
                        activeStatus: activeStatus,
                        validValues: this.VALID_STATUSES,
                        constraint: error.constraint
                    }
                });
                
                ErrorHandler.logError(validationError);
                throw validationError;
            }

            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof ConflictError) {
                throw error;
            }

            // Wrap unexpected errors
            const dbError = new DatabaseError({
                message: 'Failed to create activity record',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    userId: userId?.toString().substring(0, 50),
                    activeStatus: activeStatus,
                    errorCode: error.code
                }
            });

            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }

    /**
     * Finds activity record by user ID.
     * 
     * Retrieves the complete activity record for a user.
     * Used for status checking, analytics, and activity monitoring.
     * 
     * @async
     * @param {string} userId - UUID of the user
     * 
     * @returns {Promise<Object|null>} Activity record if found, null otherwise
     * @returns {string} return.id - User UUID
     * @returns {string} return.active_status - Current activity status
     * @returns {Date} return.last_seen - Last activity timestamp
     * @returns {number} return.login_count - Total number of logins
     * @returns {Date} return.created_at - Record creation timestamp
     * @returns {Date} return.updated_at - Last update timestamp
     * 
     * @throws {ValidationError} If userId is not a valid UUID
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * const activity = await activityRepo.findActivity(userId);
     * if (activity && activity.active_status === 'logged in') {
     *   console.log(`User last seen: ${activity.last_seen}`);
     * }
     * 
     * @example
     * // Check if user is active
     * const activity = await activityRepo.findActivity(userId);
     * const isActive = activity?.active_status === 'logged in';
     */
    async findActivity(userId) {
        const functionName = 'findActivity';

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
                SELECT id, active_status, last_seen, login_count, created_at, updated_at
                FROM user_activity
                WHERE id = $1
            `;

            const result = await this.db.query(query, [validation.sanitized]);

            return result.rows.length > 0 ? result.rows[0] : null;

        } catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to find activity record',
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
     * Finds all users with a specific activity status.
     * 
     * Retrieves all activity records matching the specified status.
     * Useful for:
     * - Getting all logged-in users
     * - Finding inactive users for cleanup
     * - Analytics and monitoring dashboards
     * 
     * @async
     * @param {string} activeStatus - Activity status to filter by
     *        Valid values: 'logged out', 'logged in', 'inactive'
     * 
     * @returns {Promise<Array>} Array of activity records
     * 
     * @throws {ValidationError} If activeStatus is invalid
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * // Get all currently logged-in users
     * const activeUsers = await activityRepo.findAllActive('logged in');
     * console.log(`${activeUsers.length} users are currently logged in`);
     * 
     * @example
     * // Find inactive users for cleanup
     * const inactiveUsers = await activityRepo.findAllActive('inactive');
     * for (const activity of inactiveUsers) {
     *   console.log(`User ${activity.id} inactive since ${activity.last_seen}`);
     * }
     */
    async findAllActive(activeStatus) {
        const functionName = 'findAllActive';

        try {
            // Validate and sanitize activeStatus
            const sanitizedStatus = this._validateActivityStatus(activeStatus, functionName);

            const query = `
                SELECT id, active_status, last_seen, login_count, created_at, updated_at
                FROM user_activity
                WHERE active_status = $1
                ORDER BY last_seen DESC
            `;

            const result = await this.db.query(query, [sanitizedStatus]);

            return result.rows || [];

        } catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to find active users',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    activeStatus: activeStatus,
                    errorCode: error.code
                }
            });

            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }

    /**
     * Updates user activity status.
     * 
     * Updates activity record with new status and automatically:
     * - Updates last_seen timestamp
     * - Updates updated_at timestamp
     * - Increments login_count if status changes to 'logged in'
     * 
     * Common Use Cases:
     * - Login: Update status to 'logged in', increment login_count
     * - Logout: Update status to 'logged out'
     * - Inactivity: Update status to 'inactive'
     * - Activity tracking: Update last_seen timestamp
     * 
     * @async
     * @param {string} userId - UUID of the user
     * @param {string} activeStatus - New activity status
     *        Valid values: 'logged out', 'logged in', 'inactive'
     * 
     * @returns {Promise<Object>} Updated activity record
     * @returns {string} return.id - User UUID
     * @returns {string} return.active_status - New activity status
     * @returns {Date} return.last_seen - Updated timestamp
     * @returns {number} return.login_count - Updated login count
     * @returns {Date} return.created_at - Original creation timestamp
     * @returns {Date} return.updated_at - New update timestamp
     * 
     * @throws {ValidationError} If userId or activeStatus is invalid
     * @throws {NotFoundError} If activity record doesn't exist
     * @throws {DatabaseError} If database operation fails
     * 
     * @example
     * // Update on login (increments login_count)
     * const updated = await activityRepo.updateActivity(userId, 'logged in');
     * console.log(`Login count: ${updated.login_count}`);
     * 
     * @example
     * // Update on logout
     * await activityRepo.updateActivity(userId, 'logged out');
     * 
     * @example
     * // Mark user as inactive
     * await activityRepo.updateActivity(userId, 'inactive');
     */
    async updateActivity(userId, activeStatus) {
        const functionName = 'updateActivity';

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

            // Validate and sanitize activeStatus
            const sanitizedStatus = this._validateActivityStatus(activeStatus, functionName);

            // Increment login_count if status is changing to 'logged in'
            const incrementLogin = sanitizedStatus === 'logged in';

            const query = `
                UPDATE user_activity
                SET 
                    active_status = $2,
                    last_seen = NOW(),
                    updated_at = NOW()
                    ${incrementLogin ? ', login_count = login_count + 1' : ''}
                WHERE id = $1
                RETURNING id, active_status, last_seen, login_count, created_at, updated_at
            `;

            const result = await this.db.query(query, [
                userIdValidation.sanitized,
                sanitizedStatus
            ]);

            if (!result.rows || result.rows.length === 0) {
                throw new NotFoundError({
                    message: 'Activity record not found',
                    className: this.className,
                    functionName,
                    details: {
                        userId: userIdValidation.sanitized,
                        hint: 'User may not have an activity record'
                    }
                });
            }

            return result.rows[0];

        } catch (error) {
            // Handle invalid status (CHECK constraint violation)
            if (error.code === '23514') {
                const validationError = new ValidationError({
                    message: 'Invalid activity status value',
                    className: this.className,
                    functionName,
                    cause: error,
                    details: {
                        activeStatus: activeStatus,
                        validValues: this.VALID_STATUSES,
                        constraint: error.constraint
                    }
                });
                
                ErrorHandler.logError(validationError);
                throw validationError;
            }

            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof NotFoundError) {
                throw error;
            }

            // Wrap unexpected errors
            const dbError = new DatabaseError({
                message: 'Failed to update activity record',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    userId: userId?.toString().substring(0, 50),
                    activeStatus: activeStatus,
                    errorCode: error.code
                }
            });

            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }

    /**
     * Deletes activity record for a user.
     * 
     * Permanently removes the activity record from the database.
     * This is typically used when deleting a user account entirely.
     * 
     * WARNING: This operation:
     * - Cannot be undone
     * - Removes all activity history and login count
     * - Should be called as part of user deletion process
     * 
     * @async
     * @param {string} userId - UUID of the user
     * 
     * @returns {Promise<boolean>} True if deleted, false if not found
     * 
     * @throws {ValidationError} If userId is not a valid UUID
     * @throws {DatabaseError} If database operation fails
     * 
     * @example
     * // Delete activity as part of user deletion
     * await databaseInstance.transaction(async (client) => {
     *   const passwordRepo = new UserPasswordRepository(client);
     *   const sessionRepo = new UserSessionRepository(client);
     *   const activityRepo = new UserActivityRepository(client);
     *   const userRepo = new UserInformationRepository(client);
     *   
     *   await passwordRepo.deletePassword(userId);
     *   await sessionRepo.deleteSessionByUserId(userId);
     *   await activityRepo.deleteActivity(userId);
     *   await userRepo.deleteUser(userId);
     * });
     */
    async deleteActivity(userId) {
        const functionName = 'deleteActivity';

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
                DELETE FROM user_activity
                WHERE id = $1
            `;

            const result = await this.db.query(query, [validation.sanitized]);

            return result.rowCount > 0;

        } catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to delete activity record',
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
     * Checks if an activity record exists for a user.
     * 
     * Useful for verifying if a user has completed activity setup
     * during registration flow.
     * 
     * @async
     * @param {string} userId - UUID of the user
     * 
     * @returns {Promise<boolean>} True if activity exists, false otherwise
     * 
     * @throws {ValidationError} If userId is not a valid UUID
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * const hasActivity = await activityRepo.activityExists(userId);
     * if (!hasActivity) {
     *   // Create activity record
     * }
     */
    async activityExists(userId) {
        const functionName = 'activityExists';

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
                SELECT EXISTS(SELECT 1 FROM user_activity WHERE id = $1) as exists
            `;

            const result = await this.db.query(query, [validation.sanitized]);

            return result.rows[0]?.exists || false;

        } catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to check activity existence',
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
     * Gets count of users by activity status.
     * 
     * Returns analytics data showing how many users are in each status.
     * Useful for dashboards and monitoring.
     * 
     * @async
     * @returns {Promise<Object>} Count of users per status
     * @returns {number} return.logged_in - Number of logged-in users
     * @returns {number} return.logged_out - Number of logged-out users
     * @returns {number} return.inactive - Number of inactive users
     * 
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * const stats = await activityRepo.getActivityStatistics();
     * console.log(`Active users: ${stats.logged_in}`);
     * console.log(`Inactive users: ${stats.inactive}`);
     */
    async getActivityStatistics() {
        const functionName = 'getActivityStatistics';

        try {
            const query = `
                SELECT 
                    active_status,
                    COUNT(*) as count
                FROM user_activity
                GROUP BY active_status
            `;

            const result = await this.db.query(query);

            // Initialize statistics object
            const stats = {
                'logged in': 0,
                'logged out': 0,
                'inactive': 0
            };

            // Populate from query results
            result.rows.forEach(row => {
                stats[row.active_status] = parseInt(row.count, 10);
            });

            return stats;

        } catch (error) {
            const dbError = new DatabaseError({
                message: 'Failed to get activity statistics',
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

    /**
     * Updates last_seen timestamp without changing status.
     * 
     * Useful for tracking user activity without changing login status.
     * Can be called on every API request to track user engagement.
     * 
     * @async
     * @param {string} userId - UUID of the user
     * 
     * @returns {Promise<Object>} Updated activity record
     * 
     * @throws {ValidationError} If userId is not a valid UUID
     * @throws {NotFoundError} If activity record doesn't exist
     * @throws {DatabaseError} If database operation fails
     * 
     * @example
     * // Update on every authenticated request
     * app.use(async (req, res, next) => {
     *   if (req.user) {
     *     await activityRepo.touchActivity(req.user.id);
     *   }
     *   next();
     * });
     */
    async touchActivity(userId) {
        const functionName = 'touchActivity';

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
                UPDATE user_activity
                SET 
                    last_seen = NOW(),
                    updated_at = NOW()
                WHERE id = $1
                RETURNING id, active_status, last_seen, login_count, created_at, updated_at
            `;

            const result = await this.db.query(query, [validation.sanitized]);

            if (!result.rows || result.rows.length === 0) {
                throw new NotFoundError({
                    message: 'Activity record not found',
                    className: this.className,
                    functionName,
                    details: {
                        userId: validation.sanitized
                    }
                });
            }

            return result.rows[0];

        } catch (error) {
            if (error instanceof ValidationError || 
                error instanceof NotFoundError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to touch activity record',
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
}

export default UserActivityRepository;
/**
 * @fileoverview User Password Repository
 * 
 * Handles all database operations related to user password management.
 * Implements the Repository Pattern to abstract password data access logic
 * from business logic, enabling secure password storage, retrieval, and history tracking.
 * 
 * SOLID Principles Applied:
 * - Single Responsibility: Only handles password data persistence
 * - Open/Closed: Extendable for new password policies without modification
 * - Liskov Substitution: Can be replaced with any IPasswordRepository implementation
 * - Interface Segregation: Focused interface for password operations only
 * - Dependency Inversion: Depends on database abstraction, not concrete implementation
 * 
 * Security Features:
 * - Stores only hashed passwords (never plain text)
 * - Maintains password history to prevent reuse
 * - JSONB storage for efficient previous password tracking
 * - No password exposure in logs or error messages
 * - SQL injection prevention through parameterized queries
 * 
 * @module repositories/user/UserPasswordRepository
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
 * Repository class for User Password data access.
 * 
 * Manages password records with:
 * - Secure password storage (hashed only)
 * - Password history tracking (prevents reuse)
 * - One-to-one relationship with users table
 * - JSONB-based previous password storage
 * - Transaction support for atomic operations
 * 
 * Database Schema:
 * - id (UUID): References users(id)
 * - current_password (TEXT): Currently active hashed password
 * - previous_passwords (JSONB): Array of previous password hashes
 * - last_updated (TIMESTAMP): Last password change timestamp
 * - created_at (TIMESTAMP): Record creation timestamp
 * 
 * @class UserPasswordRepository
 * 
 * @example
 * // Initialize repository
 * const passwordRepo = new UserPasswordRepository();
 * 
 * // Create password record
 * await passwordRepo.createPassword(userId, hashedPassword);
 * 
 * @example
 * // Use with transaction
 * await databaseInstance.transaction(async (client) => {
 *   const passwordRepo = new UserPasswordRepository(client);
 *   await passwordRepo.createPassword(userId, hashedPassword);
 * });
 */
class UserPasswordRepository {
    /**
     * Creates a new UserPasswordRepository instance.
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
     * const passwordRepo = new UserPasswordRepository();
     * 
     * @example
     * // Transaction usage (uses dedicated client)
     * await databaseInstance.transaction(async (client) => {
     *   const passwordRepo = new UserPasswordRepository(client);
     *   await passwordRepo.createPassword(userId, hashedPassword);
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
        this.className = 'UserPasswordRepository';
    }

    /**
     * Validates that a string is a valid bcrypt hash.
     * 
     * Bcrypt hashes follow the format: $2a$10$... or $2b$12$...
     * 
     * @private
     * @param {string} hash - String to validate
     * @returns {boolean} True if valid bcrypt hash format
     * 
     * @example
     * this._isValidBcryptHash('$2b$12$abcdefghijklmnopqrstuvwxyz');
     * // Returns: true
     */
    _isValidBcryptHash(hash) {
        if (!hash || typeof hash !== 'string') {
            return false;
        }

        // Bcrypt hash format: $2a$ or $2b$ followed by cost and hash
        // Total length is typically 60 characters
        const bcryptPattern = /^\$2[aby]\$\d{2}\$.{53}$/;
        return bcryptPattern.test(hash);
    }

    /**
     * Creates a new password record for a user.
     * 
     * Establishes the initial password for a user account. This should be called
     * after user registration. The password must be pre-hashed using bcrypt
     * before calling this method.
     * 
     * Security Considerations:
     * - Only accepts hashed passwords (validates bcrypt format)
     * - Creates one-to-one relationship with users table
     * - Initializes empty password history
     * - Prevents duplicate password records per user
     * 
     * @async
     * @param {string} userId - UUID of the user (must exist in users table)
     * @param {string} hashedPassword - Bcrypt hashed password (60 chars, $2a$/$2b$ format)
     * 
     * @returns {Promise<Object>} Created password record
     * @returns {string} return.id - User UUID (references users.id)
     * @returns {string} return.current_password - Hashed password
     * @returns {Array} return.previous_passwords - Empty array (initial state)
     * @returns {Date} return.last_updated - Password creation timestamp
     * @returns {Date} return.created_at - Record creation timestamp
     * 
     * @throws {ValidationError} If userId or hashedPassword is invalid
     * @throws {ConflictError} If password record already exists for user
     * @throws {DatabaseError} If user doesn't exist or database operation fails
     * 
     * @example
     * import bcrypt from 'bcrypt';
     * 
     * const hashedPassword = await bcrypt.hash('SecurePass123!', 12);
     * const passwordRecord = await passwordRepo.createPassword(
     *   '550e8400-e29b-41d4-a716-446655440000',
     *   hashedPassword
     * );
     * 
     * @example
     * // Within transaction (user creation + password)
     * await databaseInstance.transaction(async (client) => {
     *   const userRepo = new UserInformationRepository(client);
     *   const passwordRepo = new UserPasswordRepository(client);
     *   
     *   const user = await userRepo.createUser(userData);
     *   await passwordRepo.createPassword(user.id, hashedPassword);
     * });
     */
    async createPassword(userId, hashedPassword) {
        const functionName = 'createPassword';

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

            // Validate hashedPassword format
            if (!hashedPassword || typeof hashedPassword !== 'string') {
                throw new ValidationError({
                    message: 'Hashed password must be a non-empty string',
                    className: this.className,
                    functionName,
                    details: {
                        field: 'hashedPassword',
                        receivedType: typeof hashedPassword,
                        hint: 'Password must be hashed using bcrypt before storage'
                    }
                });
            }

            // Validate bcrypt hash format
            if (!this._isValidBcryptHash(hashedPassword)) {
                throw new ValidationError({
                    message: 'Invalid bcrypt hash format',
                    className: this.className,
                    functionName,
                    details: {
                        field: 'hashedPassword',
                        receivedLength: hashedPassword.length,
                        expectedFormat: '$2a$10$... or $2b$12$...',
                        hint: 'Use bcrypt.hash() to generate valid password hash'
                    }
                });
            }

            const query = `
                INSERT INTO user_passwords (id, current_password, previous_passwords)
                VALUES ($1, $2, '[]'::JSONB)
                RETURNING id, current_password, previous_passwords, last_updated, created_at
            `;

            const result = await this.db.query(query, [
                userIdValidation.sanitized,
                hashedPassword
            ]);

            if (!result.rows || result.rows.length === 0) {
                throw new DatabaseError({
                    message: 'Password creation failed - no data returned',
                    className: this.className,
                    functionName,
                    details: {
                        userId: userIdValidation.sanitized
                    }
                });
            }

            return result.rows[0];

        } catch (error) {
            // Handle duplicate password record (user already has password)
            if (error.code === '23505') {
                const conflictError = new ConflictError({
                    message: 'Password record already exists for this user',
                    className: this.className,
                    functionName,
                    cause: error,
                    details: {
                        userId: userId?.toString().substring(0, 50),
                        constraint: error.constraint,
                        hint: 'Use updatePassword() to change existing password'
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
                        hint: 'Create user record before creating password'
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
                message: 'Failed to create password record',
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
     * Finds password record by user ID.
     * 
     * Retrieves the complete password record including current password hash
     * and password history. Used for authentication and password validation.
     * 
     * Security Note: The returned password hash should ONLY be used for
     * bcrypt comparison. Never expose password hashes in API responses.
     * 
     * @async
     * @param {string} userId - UUID of the user
     * 
     * @returns {Promise<Object|null>} Password record if found, null otherwise
     * @returns {string} return.id - User UUID
     * @returns {string} return.current_password - Current bcrypt hashed password
     * @returns {Array<string>} return.previous_passwords - Array of previous password hashes
     * @returns {Date} return.last_updated - Last password change timestamp
     * @returns {Date} return.created_at - Record creation timestamp
     * 
     * @throws {ValidationError} If userId is not a valid UUID
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * const passwordRecord = await passwordRepo.findPassword(userId);
     * if (passwordRecord) {
     *   const isValid = await bcrypt.compare(
     *     plainPassword, 
     *     passwordRecord.current_password
     *   );
     * }
     * 
     * @example
     * // Check password history (prevent reuse)
     * const record = await passwordRepo.findPassword(userId);
     * for (const oldHash of record.previous_passwords) {
     *   const isReused = await bcrypt.compare(newPassword, oldHash);
     *   if (isReused) {
     *     throw new Error('Cannot reuse previous password');
     *   }
     * }
     */
    async findPassword(userId) {
        const functionName = 'findPassword';

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
                SELECT id, current_password, previous_passwords, last_updated, created_at
                FROM user_passwords
                WHERE id = $1
            `;

            const result = await this.db.query(query, [validation.sanitized]);

            return result.rows.length > 0 ? result.rows[0] : null;

        } catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to find password record',
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
     * Updates user password with history tracking.
     * 
     * Performs atomic password update operation:
     * 1. Validates new password hash format
     * 2. Moves current password to history
     * 3. Sets new password as current
     * 4. Updates last_updated timestamp
     * 
     * Password History Management:
     * - Maintains array of previous passwords in JSONB
     * - Allows password reuse prevention
     * - Can be extended with retention policies (e.g., keep last 5)
     * 
     * @async
     * @param {string} userId - UUID of the user
     * @param {string} newHashedPassword - New bcrypt hashed password
     * @param {string} [currentPassword] - Current password hash (for validation, optional)
     * 
     * @returns {Promise<Object>} Updated password record
     * @returns {string} return.id - User UUID
     * @returns {string} return.current_password - New hashed password
     * @returns {Array<string>} return.previous_passwords - Updated history array
     * @returns {Date} return.last_updated - Update timestamp
     * @returns {Date} return.created_at - Original creation timestamp
     * 
     * @throws {ValidationError} If userId or newHashedPassword is invalid
     * @throws {NotFoundError} If password record doesn't exist
     * @throws {DatabaseError} If database operation fails
     * 
     * @example
     * // Simple password update
     * const updated = await passwordRepo.updatePassword(
     *   userId,
     *   newHashedPassword
     * );
     * 
     * @example
     * // Update with history limit (keep last 5 passwords)
     * const record = await passwordRepo.findPassword(userId);
     * const previousPasswords = [
     *   record.current_password,
     *   ...record.previous_passwords.slice(0, 4) // Keep last 4
     * ];
     * 
     * await passwordRepo.updatePassword(userId, newHashedPassword);
     */
    async updatePassword(userId, newHashedPassword, currentPassword = null) {
        const functionName = 'updatePassword';

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

            // Validate new hashed password
            if (!newHashedPassword || typeof newHashedPassword !== 'string') {
                throw new ValidationError({
                    message: 'New hashed password must be a non-empty string',
                    className: this.className,
                    functionName,
                    details: {
                        field: 'newHashedPassword',
                        receivedType: typeof newHashedPassword
                    }
                });
            }

            if (!this._isValidBcryptHash(newHashedPassword)) {
                throw new ValidationError({
                    message: 'Invalid bcrypt hash format for new password',
                    className: this.className,
                    functionName,
                    details: {
                        field: 'newHashedPassword',
                        receivedLength: newHashedPassword.length,
                        expectedFormat: '$2a$10$... or $2b$12$...'
                    }
                });
            }

            // Update password and move current to history
            const query = `
                UPDATE user_passwords
                SET 
                    previous_passwords = previous_passwords || jsonb_build_array(current_password),
                    current_password = $2,
                    last_updated = NOW()
                WHERE id = $1
                RETURNING id, current_password, previous_passwords, last_updated, created_at
            `;

            const result = await this.db.query(query, [
                userIdValidation.sanitized,
                newHashedPassword
            ]);

            if (!result.rows || result.rows.length === 0) {
                throw new NotFoundError({
                    message: 'Password record not found',
                    className: this.className,
                    functionName,
                    details: {
                        userId: userIdValidation.sanitized,
                        hint: 'User may not have a password record'
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
                message: 'Failed to update password',
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
     * Deletes password record for a user.
     * 
     * Permanently removes the password record from the database.
     * This is typically used when deleting a user account entirely.
     * 
     * WARNING: This operation:
     * - Cannot be undone
     * - Removes password history
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
     * // Delete password as part of user deletion
     * await databaseInstance.transaction(async (client) => {
     *   const passwordRepo = new UserPasswordRepository(client);
     *   const sessionRepo = new UserSessionRepository(client);
     *   const activityRepo = new UserActivityRepository(client);
     *   const userRepo = new UserInformationRepository(client);
     *   
     *   await passwordRepo.deletePassword(userId);
     *   await sessionRepo.deleteAllSessions(userId);
     *   await activityRepo.deleteActivity(userId);
     *   await userRepo.deleteUser(userId);
     * });
     */
    async deletePassword(userId) {
        const functionName = 'deletePassword';

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
                DELETE FROM user_passwords
                WHERE id = $1
            `;

            const result = await this.db.query(query, [validation.sanitized]);

            return result.rowCount > 0;

        } catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to delete password record',
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
     * Checks if a password record exists for a user.
     * 
     * Useful for verifying if a user has completed password setup
     * during registration flow or account setup.
     * 
     * @async
     * @param {string} userId - UUID of the user
     * 
     * @returns {Promise<boolean>} True if password exists, false otherwise
     * 
     * @throws {ValidationError} If userId is not a valid UUID
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * const hasPassword = await passwordRepo.passwordExists(userId);
     * if (!hasPassword) {
     *   // Redirect to password setup
     * }
     */
    async passwordExists(userId) {
        const functionName = 'passwordExists';

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
                SELECT EXISTS(SELECT 1 FROM user_passwords WHERE id = $1) as exists
            `;

            const result = await this.db.query(query, [validation.sanitized]);

            return result.rows[0]?.exists || false;

        } catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to check password existence',
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
     * Gets password history count for a user.
     * 
     * Returns the number of previous passwords stored in history.
     * Useful for implementing password retention policies.
     * 
     * @async
     * @param {string} userId - UUID of the user
     * 
     * @returns {Promise<number>} Number of passwords in history
     * 
     * @throws {ValidationError} If userId is not a valid UUID
     * @throws {NotFoundError} If password record doesn't exist
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * const historyCount = await passwordRepo.getPasswordHistoryCount(userId);
     * console.log(`User has ${historyCount} previous passwords`);
     */
    async getPasswordHistoryCount(userId) {
        const functionName = 'getPasswordHistoryCount';

        try {
            const record = await this.findPassword(userId);
            
            if (!record) {
                throw new NotFoundError({
                    message: 'Password record not found',
                    className: this.className,
                    functionName,
                    details: {
                        userId: userId?.toString().substring(0, 50)
                    }
                });
            }

            return record.previous_passwords ? record.previous_passwords.length : 0;

        } catch (error) {
            if (error instanceof ValidationError || 
                error instanceof NotFoundError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to get password history count',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    userId: userId?.toString().substring(0, 50)
                }
            });

            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }
}

export default UserPasswordRepository;
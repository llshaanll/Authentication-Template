/**
 * @fileoverview User Information Repository
 * 
 * Handles all database operations related to user information management.
 * Implements the Repository Pattern to abstract data access logic from business logic,
 * making the code more testable, maintainable, and adhering to SOLID principles.
 * 
 * SOLID Principles Applied:
 * - Single Responsibility: Only handles user data persistence
 * - Open/Closed: Extendable through inheritance without modification
 * - Liskov Substitution: Can be replaced with any IRepository implementation
 * - Interface Segregation: Focused interface for user operations only
 * - Dependency Inversion: Depends on database abstraction, not concrete implementation
 * 
 * @module repositories/user/UserInformationRepository
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
 * Repository class for User Information data access.
 * 
 * Provides CRUD operations for user records with:
 * - Comprehensive input validation and sanitization
 * - SQL injection prevention through parameterized queries
 * - Custom error handling with detailed context
 * - Support for both pool and transaction-based operations
 * - UUID-based primary keys
 * 
 * @class UserInformationRepository
 * 
 * @example
 * // Initialize repository
 * const userRepo = new UserInformationRepository();
 * 
 * // Create user
 * const newUser = await userRepo.createUser({
 *   name: 'John Doe',
 *   email: 'john@example.com',
 *   contact: '+1234567890'
 * });
 * 
 * @example
 * // Use with transaction
 * await databaseInstance.transaction(async (client) => {
 *   const userRepo = new UserInformationRepository(client);
 *   const user = await userRepo.createUser(userData);
 *   // Other transactional operations...
 * });
 */
class UserInformationRepository {
    /**
     * Creates a new UserInformationRepository instance.
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
     * const userRepo = new UserInformationRepository();
     * 
     * @example
     * // Transaction usage (uses dedicated client)
     * await databaseInstance.transaction(async (client) => {
     *   const userRepo = new UserInformationRepository(client);
     *   await userRepo.createUser(userData);
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
        this.className = 'UserInformationRepository';
    }

    /**
     * Creates a new user record in the database.
     * 
     * Performs comprehensive validation before insertion:
     * - Required field validation (name, email)
     * - Email format validation
     * - Contact number format validation (if provided)
     * - SQL injection prevention
     * - XSS attack prevention
     * - Duplicate email detection
     * 
     * NOTE: This method only creates the user record. Password management
     * is handled separately by UserPasswordRepository for separation of concerns.
     * 
     * @async
     * @param {Object} userData - User data to insert
     * @param {string} userData.name - User's full name (2-255 characters)
     * @param {string} userData.email - User's email address (unique, max 320 chars)
     * @param {string} [userData.contact] - User's contact number (optional, max 20 chars)
     * 
     * @returns {Promise<Object>} Created user object with generated UUID
     * @returns {string} return.id - Generated UUID for the user
     * @returns {string} return.name - User's name
     * @returns {string} return.email - User's email (lowercase)
     * @returns {string} [return.contact] - User's contact (if provided)
     * @returns {Date} return.created_at - Timestamp of creation
     * @returns {Date} return.updated_at - Timestamp of last update
     * 
     * @throws {ValidationError} If user data validation fails
     * @throws {ConflictError} If email already exists
     * @throws {DatabaseError} If database operation fails
     * 
     * @example
     * const newUser = await userRepo.createUser({
     *   name: 'John Doe',
     *   email: 'john@example.com',
     *   contact: '+1234567890'
     * });
     * // Returns: { id: 'uuid', name: 'John Doe', email: 'john@example.com', ... }
     * 
     * @example
     * // Without contact (optional field)
     * const newUser = await userRepo.createUser({
     *   name: 'Jane Smith',
     *   email: 'jane@example.com'
     * });
     */
    async createUser(userData) {
        const functionName = 'createUser';

        try {
            // Validate and sanitize input data
            const validation = this.validator.validateUserData(userData);
            
            if (!validation.isValid) {
                throw new ValidationError({
                    message: 'User data validation failed',
                    className: this.className,
                    functionName,
                    details: {
                        validationErrors: validation.errors,
                        receivedData: {
                            name: userData?.name?.substring(0, 50),
                            email: userData?.email?.substring(0, 50),
                            hasContact: !!userData?.contact
                        }
                    }
                });
            }

            const { name, email, contact } = validation.sanitized;

            // Build dynamic query based on optional fields
            const fields = ['name', 'email'];
            const values = [name, email];
            const placeholders = ['$1', '$2'];

            if (contact !== undefined) {
                fields.push('contact');
                values.push(contact);
                placeholders.push('$3');
            }

            const query = `
                INSERT INTO users (${fields.join(', ')})
                VALUES (${placeholders.join(', ')})
                RETURNING id, name, email, contact, created_at, updated_at
            `;

            const result = await this.db.query(query, values);

            if (!result.rows || result.rows.length === 0) {
                throw new DatabaseError({
                    message: 'User creation failed - no data returned',
                    className: this.className,
                    functionName,
                    details: {
                        query: query.substring(0, 100),
                        email: email.substring(0, 50)
                    }
                });
            }

            return result.rows[0];

        } catch (error) {
            // Handle duplicate email error (PostgreSQL error code 23505)
            if (error.code === '23505' && error.constraint === 'users_email_key') {
                const conflictError = new ConflictError({
                    message: 'User with this email already exists',
                    className: this.className,
                    functionName,
                    cause: error,
                    details: {
                        email: userData?.email?.substring(0, 50),
                        constraint: error.constraint
                    }
                });
                
                ErrorHandler.logError(conflictError);
                throw conflictError;
            }

            // Re-throw if already a custom error
            if (error instanceof ValidationError || 
                error instanceof ConflictError || 
                error instanceof DatabaseError) {
                throw error;
            }

            // Wrap unexpected errors
            const dbError = new DatabaseError({
                message: 'Failed to create user record',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    email: userData?.email?.substring(0, 50),
                    errorCode: error.code,
                    errorDetail: error.detail
                }
            });

            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }

    /**
     * Finds a user by email address.
     * 
     * Performs case-insensitive email lookup with full validation.
     * 
     * @async
     * @param {string} email - Email address to search for
     * 
     * @returns {Promise<Object|null>} User object if found, null otherwise
     * @returns {string} return.id - User's UUID
     * @returns {string} return.name - User's name
     * @returns {string} return.email - User's email
     * @returns {string} [return.contact] - User's contact
     * @returns {Date} return.created_at - Creation timestamp
     * @returns {Date} return.updated_at - Last update timestamp
     * 
     * @throws {ValidationError} If email format is invalid
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * const user = await userRepo.findUserByEmail('john@example.com');
     * if (user) {
     *   console.log(`Found user: ${user.name}`);
     * } else {
     *   console.log('User not found');
     * }
     */
    async findUserByEmail(email) {
        const functionName = 'findUserByEmail';

        try {
            // Validate email format
            const sanitizedEmail = this.validator.sanitizeEmail(email);
            
            if (!this.validator._patterns.email.test(sanitizedEmail)) {
                throw new ValidationError({
                    message: 'Invalid email format',
                    className: this.className,
                    functionName,
                    details: {
                        email: sanitizedEmail.substring(0, 50)
                    }
                });
            }

            const query = `
                SELECT id, name, email, contact, created_at, updated_at
                FROM users
                WHERE LOWER(email) = LOWER($1)
            `;

            const result = await this.db.query(query, [sanitizedEmail]);

            return result.rows.length > 0 ? result.rows[0] : null;

        } catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to find user by email',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    email: email?.substring(0, 50),
                    errorCode: error.code
                }
            });

            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }

    /**
     * Finds a user by UUID.
     * 
     * @async
     * @param {string} userId - User's UUID
     * 
     * @returns {Promise<Object|null>} User object if found, null otherwise
     * 
     * @throws {ValidationError} If userId is not a valid UUID
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * const user = await userRepo.findUserById('550e8400-e29b-41d4-a716-446655440000');
     */
    async findUserById(userId) {
        const functionName = 'findUserById';

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
                SELECT id, name, email, contact, created_at, updated_at
                FROM users
                WHERE id = $1
            `;

            const result = await this.db.query(query, [validation.sanitized]);

            return result.rows.length > 0 ? result.rows[0] : null;

        } catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to find user by ID',
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
     * Finds a user by contact number.
     * 
     * @async
     * @param {string} contact - Contact number to search for
     * 
     * @returns {Promise<Object|null>} User object if found, null otherwise
     * 
     * @throws {ValidationError} If contact format is invalid
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * const user = await userRepo.findUserByContact('+1234567890');
     */
    async findUserByContact(contact) {
        const functionName = 'findUserByContact';

        try {
            // Validate contact format
            const sanitizedContact = this.validator.sanitizeString(contact);
            
            if (!this.validator._patterns.phone.test(sanitizedContact)) {
                throw new ValidationError({
                    message: 'Invalid contact number format',
                    className: this.className,
                    functionName,
                    details: {
                        contact: sanitizedContact.substring(0, 20)
                    }
                });
            }

            const query = `
                SELECT id, name, email, contact, created_at, updated_at
                FROM users
                WHERE contact = $1
            `;

            const result = await this.db.query(query, [sanitizedContact]);

            return result.rows.length > 0 ? result.rows[0] : null;

        } catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to find user by contact',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    contact: contact?.substring(0, 20),
                    errorCode: error.code
                }
            });

            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }

    /**
     * Updates user information.
     * 
     * Performs partial updates - only updates fields that are provided.
     * Fields not included in updateData remain unchanged in the database.
     * 
     * Supports updating:
     * - name: User's full name
     * - email: User's email address (must be unique)
     * - contact: User's contact number
     * 
     * @async
     * @param {string} userId - UUID of user to update
     * @param {Object} updateData - Fields to update (partial update supported)
     * @param {string} [updateData.name] - New name
     * @param {string} [updateData.email] - New email
     * @param {string} [updateData.contact] - New contact
     * 
     * @returns {Promise<Object>} Updated user object
     * 
     * @throws {ValidationError} If userId or updateData is invalid
     * @throws {NotFoundError} If user doesn't exist
     * @throws {ConflictError} If new email already exists
     * @throws {DatabaseError} If database operation fails
     * 
     * @example
     * // Update only name
     * const updated = await userRepo.updateUser(userId, {
     *   name: 'Jane Smith'
     * });
     * 
     * @example
     * // Update multiple fields
     * const updated = await userRepo.updateUser(userId, {
     *   name: 'John Updated',
     *   email: 'john.new@example.com',
     *   contact: '+9876543210'
     * });
     */
    async updateUser(userId, updateData) {
        const functionName = 'updateUser';

        try {
            // Validate userId
            const userIdValidation = this.validator.validateUUID(userId, 'User ID');
            if (!userIdValidation.isValid) {
                throw new ValidationError({
                    message: userIdValidation.error,
                    className: this.className,
                    functionName,
                    details: {
                        received: userId,
                        receivedType: typeof userId
                    }
                });
            }

            // Validate and sanitize update data
            const validation = this.validator.validatePartialUpdate(updateData);
            
            if (!validation.isValid) {
                throw new ValidationError({
                    message: 'Update data validation failed',
                    className: this.className,
                    functionName,
                    details: {
                        validationErrors: validation.errors,
                        receivedFields: Object.keys(updateData || {})
                    }
                });
            }

            const sanitizedData = validation.sanitized;

            // Check if there's anything to update
            if (Object.keys(sanitizedData).length === 0) {
                throw new ValidationError({
                    message: 'No valid fields provided for update',
                    className: this.className,
                    functionName,
                    details: {
                        receivedFields: Object.keys(updateData || {})
                    }
                });
            }

            // Build dynamic UPDATE query
            const fields = [];
            const values = [];
            let paramIndex = 1;

            Object.keys(sanitizedData).forEach(key => {
                fields.push(`${key} = $${paramIndex}`);
                values.push(sanitizedData[key]);
                paramIndex++;
            });

            // Add updated_at timestamp
            fields.push(`updated_at = NOW()`);

            // Add userId as final parameter
            values.push(userIdValidation.sanitized);

            const query = `
                UPDATE users
                SET ${fields.join(', ')}
                WHERE id = $${paramIndex}
                RETURNING id, name, email, contact, created_at, updated_at
            `;

            const result = await this.db.query(query, values);

            if (!result.rows || result.rows.length === 0) {
                throw new NotFoundError({
                    message: 'User not found',
                    className: this.className,
                    functionName,
                    details: {
                        userId: userIdValidation.sanitized
                    }
                });
            }

            return result.rows[0];

        } catch (error) {
            // Handle duplicate email error
            if (error.code === '23505' && error.constraint === 'users_email_key') {
                const conflictError = new ConflictError({
                    message: 'Email address already in use',
                    className: this.className,
                    functionName,
                    cause: error,
                    details: {
                        email: updateData?.email?.substring(0, 50),
                        constraint: error.constraint
                    }
                });
                
                ErrorHandler.logError(conflictError);
                throw conflictError;
            }

            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof NotFoundError || 
                error instanceof ConflictError) {
                throw error;
            }

            // Wrap unexpected errors
            const dbError = new DatabaseError({
                message: 'Failed to update user',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    userId: userId?.toString().substring(0, 50),
                    updateFields: Object.keys(updateData || {}),
                    errorCode: error.code
                }
            });

            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }

    /**
     * Deletes a user by UUID.
     * 
     * Performs hard delete - permanently removes user record from database.
     * 
     * WARNING: This will fail if foreign key constraints exist (user_passwords,
     * user_activity, user_sessions). Delete related records first or use
     * CASCADE delete in your schema.
     * 
     * @async
     * @param {string} userId - UUID of user to delete
     * 
     * @returns {Promise<boolean>} True if deleted, false if not found
     * 
     * @throws {ValidationError} If userId is not a valid UUID
     * @throws {DatabaseError} If database operation fails or foreign key constraint violated
     * 
     * @example
     * const deleted = await userRepo.deleteUser('550e8400-e29b-41d4-a716-446655440000');
     * if (deleted) {
     *   console.log('User deleted successfully');
     * } else {
     *   console.log('User not found');
     * }
     */
    async deleteUser(userId) {
        const functionName = 'deleteUser';

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
                DELETE FROM users
                WHERE id = $1
            `;

            const result = await this.db.query(query, [validation.sanitized]);

            return result.rowCount > 0;

        } catch (error) {
            // Handle foreign key constraint violation
            if (error.code === '23503') {
                const dbError = new DatabaseError({
                    message: 'Cannot delete user - related records exist',
                    className: this.className,
                    functionName,
                    cause: error,
                    details: {
                        userId: userId?.toString().substring(0, 50),
                        constraint: error.constraint,
                        hint: 'Delete related records (passwords, activity, sessions) first or use CASCADE'
                    }
                });
                
                ErrorHandler.logError(dbError);
                throw dbError;
            }

            if (error instanceof ValidationError) {
                throw error;
            }

            const dbError = new DatabaseError({
                message: 'Failed to delete user',
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

export default UserInformationRepository;
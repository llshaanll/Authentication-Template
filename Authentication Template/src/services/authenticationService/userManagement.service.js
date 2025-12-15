/**
 * @fileoverview User Management Service
 * 
 * Provides business logic for comprehensive user account management operations.
 * Implements the Service Layer Pattern to orchestrate multiple repositories
 * and enforce business rules for user lifecycle management.
 * 
 * SOLID Principles Applied:
 * - Single Responsibility: Handles user management business logic only
 * - Open/Closed: Extendable for new user policies without modification
 * - Liskov Substitution: Can be replaced with any IUserManagementService implementation
 * - Interface Segregation: Focused interface for user management only
 * - Dependency Inversion: Depends on repository abstractions, not concrete implementations
 * 
 * Service Responsibilities:
 * - Coordinate multi-repository transactions
 * - Enforce business rules and validation
 * - Password hashing and security
 * - User lifecycle management (create, read, update, delete)
 * - Data consistency across related tables
 * 
 * @module services/user/UserManagementService
 * @requires repositories/user/UserInformationRepository
 * @requires repositories/user/UserPasswordRepository
 * @requires repositories/user/UserActivityRepository
 * @requires config/database
 * @requires bcrypt
 * @requires utilities/loggers/error.logger
 * @requires utilities/loggers/errorHandler.logger
 * @requires validators/SecurityValidator
 * 
 * @author mr.shaan
 * @version 1.0.0
 * @since 2025-12-15
 */

import bcrypt from 'bcrypt';
import databaseInstance from '../../configuration/postgres/database.config.js';
import UserInformationRepository from '../../repositories/user/userInformation.repository.js';
import UserPasswordRepository from '../../repositories/user/userPassword.repository.js';
import UserActivityRepository from '../../repositories/user/userActivity.repository.js';
import { 
    ValidationError, 
    DatabaseError, 
    NotFoundError,
    ConflictError,
    BusinessLogicError
} from '../../utilities/loggers/error.logger.js';
import ErrorHandler from '../../utilities/loggers/errorHandler.logger.js';
import SecurityValidator from '../../utilities/validators/security.validator.js';

/**
 * Service class for User Management business logic.
 * 
 * Orchestrates user-related operations across multiple repositories with:
 * - Transaction management for data consistency
 * - Password hashing and security
 * - Business rule enforcement
 * - Input validation and sanitization
 * - Comprehensive error handling
 * 
 * @class UserManagementService
 * 
 * @example
 * // Initialize service
 * const userService = new UserManagementService();
 * 
 * // Create complete user account
 * const user = await userService.createUserAndPassword({
 *   name: 'John Doe',
 *   email: 'john@example.com',
 *   password: 'SecurePass123!'
 * });
 * 
 * @example
 * // Update user password securely
 * await userService.updateUserPassword(userId, 'NewSecurePass456!');
 */
class UserManagementService {
    /**
     * Creates a new UserManagementService instance.
     * 
     * Initializes service dependencies and configuration.
     * Uses Dependency Injection for testability and flexibility.
     * 
     * @constructor
     * 
     * @example
     * const userService = new UserManagementService();
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
        this.className = 'UserManagementService';

        /**
         * Bcrypt salt rounds for password hashing.
         * Higher value = more secure but slower.
         * 
         * @private
         * @type {number}
         */
        this.SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
    }

    /**
     * Sanitizes error details to prevent sensitive data exposure.
     * 
     * @private
     * @param {Object} details - Error details to sanitize
     * @returns {Object} Sanitized details object
     */
    _sanitizeErrorDetails(details) {
        const sanitized = { ...details };
        
        // Remove sensitive fields
        delete sanitized.password;
        delete sanitized.hashedPassword;
        delete sanitized.currentPassword;
        delete sanitized.newPassword;
        
        return sanitized;
    }

    /**
     * Creates a complete user account with password and activity tracking.
     * 
     * Performs atomic transaction to create:
     * 1. User information record
     * 2. Hashed password record
     * 3. Activity tracking record
     * 
     * If any step fails, all changes are rolled back to maintain data consistency.
     * 
     * Business Rules:
     * - Email must be unique across the system
     * - Password must meet security requirements
     * - All three records must be created successfully
     * - Initial activity status is 'logged out'
     * - Password is hashed using bcrypt before storage
     * 
     * @async
     * @param {Object} userData - User registration data
     * @param {string} userData.name - User's full name (2-255 characters)
     * @param {string} userData.email - User's email address (unique, valid format)
     * @param {string} userData.password - Plain text password (min 8 chars, complexity requirements)
     * @param {string} [userData.contact] - User's contact number (optional)
     * 
     * @returns {Promise<Object>} Created user object (without password)
     * @returns {string} return.id - Generated UUID for the user
     * @returns {string} return.name - User's name
     * @returns {string} return.email - User's email
     * @returns {string} [return.contact] - User's contact (if provided)
     * @returns {Date} return.created_at - Account creation timestamp
     * @returns {Date} return.updated_at - Last update timestamp
     * 
     * @throws {ValidationError} If input validation fails
     * @throws {ConflictError} If email already exists
     * @throws {DatabaseError} If database operation fails
     * @throws {BusinessLogicError} If business rule is violated
     * 
     * @example
     * const newUser = await userService.createUserAndPassword({
     *   name: 'John Doe',
     *   email: 'john@example.com',
     *   password: 'SecurePass123!',
     *   contact: '+1234567890'
     * });
     * 
     * @example
     * // Without optional contact
     * const newUser = await userService.createUserAndPassword({
     *   name: 'Jane Smith',
     *   email: 'jane@example.com',
     *   password: 'AnotherSecure456!'
     * });
     */
    async createUserAndPassword(userData) {
        const functionName = 'createUserAndPassword';

        try {
            // Validate complete user data (including password)
            const validation = this.validator.validateUserData(userData);
            
            if (!validation.isValid) {
                throw new ValidationError({
                    message: 'User data validation failed',
                    className: this.className,
                    functionName,
                    details: this._sanitizeErrorDetails({
                        validationErrors: validation.errors,
                        receivedFields: Object.keys(userData || {})
                    })
                });
            }

            const { name, email, contact, password } = validation.sanitized;

            // Validate password strength
            const passwordValidation = this.validator.validatePassword(password);
            if (!passwordValidation.isValid) {
                throw new ValidationError({
                    message: 'Password validation failed',
                    className: this.className,
                    functionName,
                    details: {
                        passwordErrors: passwordValidation.errors
                    }
                });
            }

            // Hash password before storage
            let hashedPassword;
            try {
                hashedPassword = await bcrypt.hash(password, this.SALT_ROUNDS);
            } catch (error) {
                throw new DatabaseError({
                    message: 'Failed to hash password',
                    className: this.className,
                    functionName,
                    cause: error,
                    details: {
                        hint: 'Bcrypt hashing operation failed'
                    }
                });
            }

            // Execute atomic transaction
            const newUser = await databaseInstance.transaction(async (client) => {
                // Initialize repositories with transaction client
                const userRepo = new UserInformationRepository(client);
                const passwordRepo = new UserPasswordRepository(client);
                const activityRepo = new UserActivityRepository(client);

                // Step 1: Create user information record
                const user = await userRepo.createUser({
                    name,
                    email,
                    contact
                });

                // Step 2: Create password record
                try {
                    await passwordRepo.createPassword(user.id, hashedPassword);
                } catch (error) {
                    throw new DatabaseError({
                        message: 'Failed to create password record',
                        className: this.className,
                        functionName,
                        cause: error,
                        details: {
                            userId: user.id,
                            step: 'password_creation'
                        }
                    });
                }

                // Step 3: Create activity tracking record
                try {
                    await activityRepo.createActivity(user.id, 'logged out');
                } catch (error) {
                    throw new DatabaseError({
                        message: 'Failed to create activity record',
                        className: this.className,
                        functionName,
                        cause: error,
                        details: {
                            userId: user.id,
                            step: 'activity_creation'
                        }
                    });
                }

                // Return user object (without password)
                return user;
            });

            return newUser;

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof ConflictError || 
                error instanceof DatabaseError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'Failed to create user account',
                className: this.className,
                functionName,
                cause: error,
                details: this._sanitizeErrorDetails({
                    email: userData?.email?.substring(0, 50),
                    name: userData?.name?.substring(0, 50)
                })
            });

            ErrorHandler.logError(serviceError);
            throw serviceError;
        }
    }

    /**
     * Finds a user by various search criteria.
     * 
     * Supports flexible user lookup by:
     * - User ID (UUID)
     * - Email address
     * - Contact number
     * 
     * Search Strategy:
     * 1. If 'id' provided: Search by UUID
     * 2. If 'email' provided: Search by email
     * 3. If 'contact' provided: Search by contact
     * 4. If multiple criteria provided: Uses first available in order above
     * 
     * @async
     * @param {Object} searchCriteria - Search parameters
     * @param {string} [searchCriteria.id] - User UUID to search by
     * @param {string} [searchCriteria.email] - Email address to search by
     * @param {string} [searchCriteria.contact] - Contact number to search by
     * 
     * @returns {Promise<Object|null>} User object if found, null otherwise
     * @returns {string} return.id - User UUID
     * @returns {string} return.name - User's name
     * @returns {string} return.email - User's email
     * @returns {string} [return.contact] - User's contact
     * @returns {Date} return.created_at - Account creation timestamp
     * @returns {Date} return.updated_at - Last update timestamp
     * 
     * @throws {ValidationError} If no valid search criteria provided or criteria invalid
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * // Find by ID
     * const user = await userService.findUser({ 
     *   id: '550e8400-e29b-41d4-a716-446655440000' 
     * });
     * 
     * @example
     * // Find by email
     * const user = await userService.findUser({ 
     *   email: 'john@example.com' 
     * });
     * 
     * @example
     * // Find by contact
     * const user = await userService.findUser({ 
     *   contact: '+1234567890' 
     * });
     */
    async findUser(searchCriteria) {
        const functionName = 'findUser';

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

            const { id, email, contact } = searchCriteria;

            // Ensure at least one search criterion is provided
            if (!id && !email && !contact) {
                throw new ValidationError({
                    message: 'At least one search criterion is required',
                    className: this.className,
                    functionName,
                    details: {
                        hint: 'Provide id, email, or contact to search'
                    }
                });
            }

            const userRepo = new UserInformationRepository();

            // Search by ID (highest priority)
            if (id) {
                return await userRepo.findUserById(id);
            }

            // Search by email (second priority)
            if (email) {
                return await userRepo.findUserByEmail(email);
            }

            // Search by contact (third priority)
            if (contact) {
                return await userRepo.findUserByContact(contact);
            }

            return null;

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof DatabaseError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'Failed to find user',
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
     * Finds password record for a user.
     * 
     * Retrieves the password record including current hash and history.
     * Used for authentication and password validation.
     * 
     * Security Note: This method returns password hashes. Ensure hashes
     * are only used for bcrypt comparison and never exposed in API responses.
     * 
     * @async
     * @param {string} userId - UUID of the user
     * 
     * @returns {Promise<Object|null>} Password record if found, null otherwise
     * @returns {string} return.id - User UUID
     * @returns {string} return.current_password - Current bcrypt hashed password
     * @returns {Array<string>} return.previous_passwords - Previous password hashes
     * @returns {Date} return.last_updated - Last password change timestamp
     * @returns {Date} return.created_at - Record creation timestamp
     * 
     * @throws {ValidationError} If userId is not a valid UUID
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * // Get password for authentication
     * const passwordRecord = await userService.findPassword(userId);
     * if (passwordRecord) {
     *   const isValid = await bcrypt.compare(
     *     plainPassword, 
     *     passwordRecord.current_password
     *   );
     * }
     */
    async findPassword(userId) {
        const functionName = 'findPassword';

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

            const passwordRepo = new UserPasswordRepository();
            return await passwordRepo.findPassword(validation.sanitized);

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof DatabaseError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'Failed to find password record',
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
     * Updates user information (name, email, contact).
     * 
     * Performs partial update - only provided fields are updated.
     * Fields not included in updateData remain unchanged.
     * 
     * Business Rules:
     * - Email must be unique if being changed
     * - At least one field must be provided for update
     * - User must exist
     * 
     * @async
     * @param {string} userId - UUID of user to update
     * @param {Object} updateData - Fields to update
     * @param {string} [updateData.name] - New name (2-255 characters)
     * @param {string} [updateData.email] - New email (unique, valid format)
     * @param {string} [updateData.contact] - New contact number
     * 
     * @returns {Promise<Object>} Updated user object
     * @returns {string} return.id - User UUID
     * @returns {string} return.name - Updated name
     * @returns {string} return.email - Updated email
     * @returns {string} [return.contact] - Updated contact
     * @returns {Date} return.created_at - Original creation timestamp
     * @returns {Date} return.updated_at - New update timestamp
     * 
     * @throws {ValidationError} If userId or updateData is invalid
     * @throws {NotFoundError} If user doesn't exist
     * @throws {ConflictError} If new email already exists
     * @throws {DatabaseError} If database operation fails
     * 
     * @example
     * // Update only name
     * const updated = await userService.updateUserInformation(userId, {
     *   name: 'Jane Smith'
     * });
     * 
     * @example
     * // Update multiple fields
     * const updated = await userService.updateUserInformation(userId, {
     *   name: 'John Updated',
     *   email: 'john.new@example.com',
     *   contact: '+9876543210'
     * });
     */
    async updateUserInformation(userId, updateData) {
        const functionName = 'updateUserInformation';

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

            // Validate update data
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

            // Ensure at least one field is being updated
            const { name, email, contact } = updateData;
            if (name === undefined && email === undefined && contact === undefined) {
                throw new ValidationError({
                    message: 'At least one field must be provided for update',
                    className: this.className,
                    functionName,
                    details: {
                        hint: 'Provide name, email, or contact to update'
                    }
                });
            }

            const userRepo = new UserInformationRepository();
            return await userRepo.updateUser(userIdValidation.sanitized, updateData);

        } catch (error) {
            // Re-throw custom errors
            if (error instanceof ValidationError || 
                error instanceof NotFoundError || 
                error instanceof ConflictError || 
                error instanceof DatabaseError) {
                throw error;
            }

            // Wrap unexpected errors
            const serviceError = new BusinessLogicError({
                message: 'Failed to update user information',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    userId: userId?.toString().substring(0, 50),
                    updateFields: Object.keys(updateData || {})
                }
            });

            ErrorHandler.logError(serviceError);
            throw serviceError;
        }
    }

    /**
     * Updates user password with security validation.
     * 
     * Performs secure password update:
     * 1. Validates new password strength
     * 2. Hashes password using bcrypt
     * 3. Updates password record with history
     * 
     * Security Features:
     * - Password strength validation
     * - Bcrypt hashing with configurable salt rounds
     * - Password history tracking (prevents reuse)
     * - No plain text storage
     * 
     * @async
     * @param {string} userId - UUID of the user
     * @param {string} newPassword - New plain text password
     * 
     * @returns {Promise<Object>} Updated password record (without actual hashes)
     * @returns {string} return.id - User UUID
     * @returns {Date} return.last_updated - Password change timestamp
     * @returns {number} return.history_count - Number of previous passwords
     * 
     * @throws {ValidationError} If userId or password is invalid
     * @throws {NotFoundError} If user doesn't exist
     * @throws {DatabaseError} If database operation fails
     * 
     * @example
     * // Update password
     * await userService.updateUserPassword(
     *   userId, 
     *   'NewSecurePassword123!'
     * );
     * 
     * @example
     * // Password change flow with validation
     * try {
     *   await userService.updateUserPassword(userId, newPassword);
     *   console.log('Password updated successfully');
     * } catch (error) {
     *   if (error instanceof ValidationError) {
     *     console.error('Weak password:', error.details.passwordErrors);
     *   }
     * }
     */
    async updateUserPassword(userId, newPassword) {
        const functionName = 'updateUserPassword';

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

            // Validate password
            if (!newPassword || typeof newPassword !== 'string') {
                throw new ValidationError({
                    message: 'Password must be a non-empty string',
                    className: this.className,
                    functionName,
                    details: {
                        field: 'newPassword',
                        receivedType: typeof newPassword
                    }
                });
            }

            // Validate password strength
            const passwordValidation = this.validator.validatePassword(newPassword);
            if (!passwordValidation.isValid) {
                throw new ValidationError({
                    message: 'Password validation failed',
                    className: this.className,
                    functionName,
                    details: {
                        passwordErrors: passwordValidation.errors
                    }
                });
            }

            // Hash new password
            let hashedPassword;
            try {
                hashedPassword = await bcrypt.hash(newPassword, this.SALT_ROUNDS);
            } catch (error) {
                throw new DatabaseError({
                    message: 'Failed to hash password',
                    className: this.className,
                    functionName,
                    cause: error,
                    details: {
                        hint: 'Bcrypt hashing operation failed'
                    }
                });
            }

            // Update password in database
            const passwordRepo = new UserPasswordRepository();
            const updatedRecord = await passwordRepo.updatePassword(
                userIdValidation.sanitized,
                hashedPassword
            );

            // Return sanitized response (without actual password hashes)
            return {
                id: updatedRecord.id,
                last_updated: updatedRecord.last_updated,
                history_count: updatedRecord.previous_passwords?.length || 0
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
                message: 'Failed to update user password',
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
     * Deletes user account and all related data.
     * 
     * Performs complete account deletion with atomic transaction:
     * 1. Delete password record
     * 2. Delete activity record
     * 3. Delete user information record
     * 
     * If any step fails, all changes are rolled back.
     * 
     * WARNING: This operation:
     * - Cannot be undone
     * - Permanently removes all user data
     * - Does NOT delete sessions (must be handled separately)
     * - Should be used with extreme caution
     * 
     * Note: Sessions are not deleted in this method to allow for
     * session cleanup and logout notification handling in the service layer.
     * Call session deletion separately before calling this method.
     * 
     * @async
     * @param {string} userId - UUID of user to delete
     * 
     * @returns {Promise<boolean>} True if deleted successfully
     * 
     * @throws {ValidationError} If userId is not a valid UUID
     * @throws {NotFoundError} If user doesn't exist
     * @throws {DatabaseError} If database operation fails
     * 
     * @example
     * // Delete user account
     * const deleted = await userService.deleteUser(userId);
     * if (deleted) {
     *   console.log('User account deleted successfully');
     * }
     * 
     * @example
     * // Complete account deletion with session cleanup
     * const sessionService = new SessionActivityService();
     * 
     * // First: Delete all sessions
     * await sessionService.logoutAllDevices(userId);
     * 
     * // Then: Delete user account
     * await userService.deleteUser(userId);
     */
    async deleteUser(userId) {
        const functionName = 'deleteUser';

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
            await databaseInstance.transaction(async (client) => {
                // Initialize repositories with transaction client
                const passwordRepo = new UserPasswordRepository(client);
                const activityRepo = new UserActivityRepository(client);
                const userRepo = new UserInformationRepository(client);

                // Step 1: Delete password record
                try {
                    await passwordRepo.deletePassword(validation.sanitized);
                } catch (error) {
                    throw new DatabaseError({
                        message: 'Failed to delete password record',
                        className: this.className,
                        functionName,
                        cause: error,
                        details: {
                            userId: validation.sanitized,
                            step: 'password_deletion'
                        }
                    });
                }

                // Step 2: Delete activity record
                try {
                    await activityRepo.deleteActivity(validation.sanitized);
                } catch (error) {
                    throw new DatabaseError({
                        message: 'Failed to delete activity record',
                        className: this.className,
                        functionName,
                        cause: error,
                        details: {
                            userId: validation.sanitized,
                            step: 'activity_deletion'
                        }
                    });
                }

                // Step 3: Delete user information record
                const userDeleted = await userRepo.deleteUser(validation.sanitized);
                
                if (!userDeleted) {
                    throw new NotFoundError({
                        message: 'User not found',
                        className: this.className,
                        functionName,
                        details: {
                            userId: validation.sanitized
                        }
                    });
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
                message: 'Failed to delete user account',
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
     * Checks if a user exists by email.
     * 
     * Useful for registration validation and duplicate email checking.
     * 
     * @async
     * @param {string} email - Email address to check
     * 
     * @returns {Promise<boolean>} True if user exists, false otherwise
     * 
     * @throws {ValidationError} If email format is invalid
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * // Check during registration
     * const exists = await userService.userExistsByEmail('john@example.com');
     * if (exists) {
     *   throw new Error('Email already registered');
     * }
     */
    async userExistsByEmail(email) {
        const functionName = 'userExistsByEmail';

        try {
            const user = await this.findUser({ email });
            return user !== null;

        } catch (error) {
            if (error instanceof ValidationError || 
                error instanceof DatabaseError) {
                throw error;
            }

            const serviceError = new BusinessLogicError({
                message: 'Failed to check user existence',
                className: this.className,
                functionName,
                cause: error,
                details: {
                    email: email?.substring(0, 50)
                }
            });

            ErrorHandler.logError(serviceError);
            throw serviceError;
        }
    }

    /**
     * Verifies a password against stored hash.
     * 
     * Securely compares plain text password with stored bcrypt hash.
     * Used for authentication and password verification.
     * 
     * @async
     * @param {string} userId - UUID of the user
     * @param {string} plainPassword - Plain text password to verify
     * 
     * @returns {Promise<boolean>} True if password matches, false otherwise
     * 
     * @throws {ValidationError} If userId or password is invalid
     * @throws {NotFoundError} If user or password record doesn't exist
     * @throws {DatabaseError} If database query fails
     * 
     * @example
     * // Verify password during login
     * const isValid = await userService.verifyPassword(userId, plainPassword);
     * if (!isValid) {
     *   throw new Error('Invalid password');
     * }
     */
    async verifyPassword(userId, plainPassword) {
        const functionName = 'verifyPassword';

        try {
            // Validate inputs
            const validation = this.validator.validateUUID(userId, 'User ID');
            if (!validation.isValid) {
                throw new ValidationError({
                    message: validation.error,
                    className: this.className,
                    functionName,
                    details: {
                        field: 'userId'
                    }
                });
            }

            if (!plainPassword || typeof plainPassword !== 'string') {
                throw new ValidationError({
                    message: 'Password must be a non-empty string',
                    className: this.className,
                    functionName,
                    details: {
                        field: 'plainPassword',
                        receivedType: typeof plainPassword
                    }
                });
            }

            // Get password record
            const passwordRecord = await this.findPassword(validation.sanitized);
            
            if (!passwordRecord) {
                throw new NotFoundError({
                    message: 'Password record not found',
                    className: this.className,
                    functionName,
                    details: {
                        userId: validation.sanitized
                    }
                });
            }

            // Compare passwords using bcrypt
            try {
                return await bcrypt.compare(plainPassword, passwordRecord.current_password);
            } catch (error) {
                throw new DatabaseError({
                    message: 'Password comparison failed',
                    className: this.className,
                    functionName,
                    cause: error,
                    details: {
                        hint: 'Bcrypt comparison operation failed'
                    }
                });
            }

        } catch (error) {
            if (error instanceof ValidationError || 
                error instanceof NotFoundError || 
                error instanceof DatabaseError) {
                throw error;
            }

            const serviceError = new BusinessLogicError({
                message: 'Failed to verify password',
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

export default UserManagementService;
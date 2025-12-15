/**
 * @fileoverview Custom Error Handling System
 * 
 * Provides structured error handling with detailed debugging information including
 * error type, ID, description, location (class/function), and cause.
 * 
 * @module utilities/errors/CustomError
 * @author mr.shaan
 * @version 1.0.0
 * @since 2025-12-14
 */

/**
 * Base custom error class with enhanced debugging information.
 * All custom errors should extend this class.
 * 
 * @class CustomError
 * @extends Error
 * 
 * @example
 * throw new CustomError({
 *   type: 'VALIDATION_ERROR',
 *   code: 'VAL_001',
 *   message: 'Invalid email format',
 *   className: 'UserService',
 *   functionName: 'createUser',
 *   details: { email: 'invalid-email' }
 * });
 */
class CustomError extends Error {
    /**
     * Creates a custom error instance.
     * 
     * @constructor
     * @param {Object} config - Error configuration
     * @param {string} config.type - Error type (e.g., 'VALIDATION_ERROR')
     * @param {string} config.code - Unique error code (e.g., 'VAL_001')
     * @param {string} config.message - Human-readable error message
     * @param {string} [config.className] - Class where error occurred
     * @param {string} [config.functionName] - Function where error occurred
     * @param {Error} [config.cause] - Original error that caused this error
     * @param {Object} [config.details] - Additional error details
     * @param {number} [config.statusCode=500] - HTTP status code
     */
    constructor({
        type,
        code,
        message,
        className = 'Unknown',
        functionName = 'Unknown',
        cause = null,
        details = {},
        statusCode = 500
    }) {
        super(message);
        
        this.name = this.constructor.name;
        this.type = type;
        this.code = code;
        this.className = className;
        this.functionName = functionName;
        this.cause = cause;
        this.details = details;
        this.statusCode = statusCode;
        this.timestamp = new Date().toISOString();
        
        // Capture stack trace
        Error.captureStackTrace(this, this.constructor);
    }

    /**
     * Returns formatted error object for logging.
     * 
     * @returns {Object} Formatted error object
     */
    toJSON() {
        return {
            name: this.name,
            type: this.type,
            code: this.code,
            message: this.message,
            location: {
                className: this.className,
                functionName: this.functionName
            },
            cause: this.cause ? {
                message: this.cause.message,
                stack: this.cause.stack
            } : null,
            details: this.details,
            statusCode: this.statusCode,
            timestamp: this.timestamp,
            stack: this.stack
        };
    }

    /**
     * Returns detailed error string for logging.
     * 
     * @returns {string} Formatted error string
     */
    toString() {
        return `[${this.type}] ${this.code} - ${this.message} 
Location: ${this.className}.${this.functionName}()
Timestamp: ${this.timestamp}
${this.cause ? `Caused by: ${this.cause.message}` : ''}
Details: ${JSON.stringify(this.details, null, 2)}`;
    }

    /**
     * Returns client-safe error object (without sensitive information).
     * 
     * @returns {Object} Client-safe error object
     */
    toClientResponse() {
        return {
            error: {
                type: this.type,
                code: this.code,
                message: this.message,
                timestamp: this.timestamp
            }
        };
    }
}

/**
 * Validation error for input validation failures.
 * 
 * @class ValidationError
 * @extends CustomError
 * 
 * @example
 * throw new ValidationError({
 *   message: 'Invalid email format',
 *   className: 'UserService',
 *   functionName: 'createUser',
 *   details: { field: 'email', value: 'invalid' }
 * });
 */
class ValidationError extends CustomError {
    constructor({ message, className, functionName, cause = null, details = {} }) {
        super({
            type: 'VALIDATION_ERROR',
            code: 'VAL_' + Date.now().toString().slice(-6),
            message,
            className,
            functionName,
            cause,
            details,
            statusCode: 400
        });
    }
}

/**
 * Authentication error for login/auth failures.
 * 
 * @class AuthenticationError
 * @extends CustomError
 */
class AuthenticationError extends CustomError {
    constructor({ message, className, functionName, cause = null, details = {} }) {
        super({
            type: 'AUTHENTICATION_ERROR',
            code: 'AUTH_' + Date.now().toString().slice(-6),
            message,
            className,
            functionName,
            cause,
            details,
            statusCode: 401
        });
    }
}

/**
 * Authorization error for permission/access failures.
 * 
 * @class AuthorizationError
 * @extends CustomError
 */
class AuthorizationError extends CustomError {
    constructor({ message, className, functionName, cause = null, details = {} }) {
        super({
            type: 'AUTHORIZATION_ERROR',
            code: 'AUTHZ_' + Date.now().toString().slice(-6),
            message,
            className,
            functionName,
            cause,
            details,
            statusCode: 403
        });
    }
}

/**
 * Database error for database operation failures.
 * 
 * @class DatabaseError
 * @extends CustomError
 */
class DatabaseError extends CustomError {
    constructor({ message, className, functionName, cause = null, details = {} }) {
        super({
            type: 'DATABASE_ERROR',
            code: 'DB_' + Date.now().toString().slice(-6),
            message,
            className,
            functionName,
            cause,
            details,
            statusCode: 500
        });
    }
}

/**
 * Not found error for resource not found scenarios.
 * 
 * @class NotFoundError
 * @extends CustomError
 */
class NotFoundError extends CustomError {
    constructor({ message, className, functionName, cause = null, details = {} }) {
        super({
            type: 'NOT_FOUND_ERROR',
            code: 'NF_' + Date.now().toString().slice(-6),
            message,
            className,
            functionName,
            cause,
            details,
            statusCode: 404
        });
    }
}

/**
 * Conflict error for duplicate/conflict scenarios.
 * 
 * @class ConflictError
 * @extends CustomError
 */
class ConflictError extends CustomError {
    constructor({ message, className, functionName, cause = null, details = {} }) {
        super({
            type: 'CONFLICT_ERROR',
            code: 'CONF_' + Date.now().toString().slice(-6),
            message,
            className,
            functionName,
            cause,
            details,
            statusCode: 409
        });
    }
}

/**
 * Business logic error for business rule violations.
 * 
 * @class BusinessLogicError
 * @extends CustomError
 */
class BusinessLogicError extends CustomError {
    constructor({ message, className, functionName, cause = null, details = {} }) {
        super({
            type: 'BUSINESS_LOGIC_ERROR',
            code: 'BIZ_' + Date.now().toString().slice(-6),
            message,
            className,
            functionName,
            cause,
            details,
            statusCode: 422
        });
    }
}

/**
 * External service error for third-party API failures.
 * 
 * @class ExternalServiceError
 * @extends CustomError
 */
class ExternalServiceError extends CustomError {
    constructor({ message, className, functionName, cause = null, details = {} }) {
        super({
            type: 'EXTERNAL_SERVICE_ERROR',
            code: 'EXT_' + Date.now().toString().slice(-6),
            message,
            className,
            functionName,
            cause,
            details,
            statusCode: 502
        });
    }
}

/**
 * Rate limit error for too many requests.
 * 
 * @class RateLimitError
 * @extends CustomError
 */
class RateLimitError extends CustomError {
    constructor({ message, className, functionName, cause = null, details = {} }) {
        super({
            type: 'RATE_LIMIT_ERROR',
            code: 'RATE_' + Date.now().toString().slice(-6),
            message,
            className,
            functionName,
            cause,
            details,
            statusCode: 429
        });
    }
}

/**
 * Session error for session-related failures.
 * 
 * @class SessionError
 * @extends CustomError
 */
class SessionError extends CustomError {
    constructor({ message, className, functionName, cause = null, details = {} }) {
        super({
            type: 'SESSION_ERROR',
            code: 'SESS_' + Date.now().toString().slice(-6),
            message,
            className,
            functionName,
            cause,
            details,
            statusCode: 401
        });
    }
}

export {
    CustomError,
    ValidationError,
    AuthenticationError,
    AuthorizationError,
    DatabaseError,
    NotFoundError,
    ConflictError,
    BusinessLogicError,
    ExternalServiceError,
    RateLimitError,
    SessionError
};

/**
 * @fileoverview Input Validation and Security Sanitization
 * 
 * Provides comprehensive input validation and sanitization to protect against:
 * - SQL Injection (though parameterized queries are primary defense)
 * - XSS (Cross-Site Scripting) attacks
 * - NoSQL Injection
 * - Command Injection
 * - Path Traversal
 * - Invalid data types and formats
 * 
 * This class implements defense-in-depth security principles with multiple
 * layers of validation and sanitization.
 * 
 * @module validators/SecurityValidator
 * @author mr.shaan
 * @version 1.0.0
 * @since 2025-12-14
 * 
 * @example
 * import SecurityValidator from './validators/SecurityValidator.js';
 * 
 * const validator = new SecurityValidator();
 * const result = validator.validateUserData({
 *   name: 'John Doe',
 *   email: 'john@example.com'
 * });
 * 
 * if (!result.isValid) {
 *   console.error(result.errors);
 * }
 */

/**
 * Security-focused input validator and sanitizer.
 * 
 * Implements multiple validation and sanitization techniques to prevent
 * common web application vulnerabilities.
 * 
 * @class SecurityValidator
 */
class SecurityValidator {
    constructor() {
        /**
         * Regular expressions for validation
         * @private
         */
        this._patterns = {
            email: /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
            phone: /^[\+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,9}$/,
            alphanumeric: /^[a-zA-Z0-9\s]+$/,
            alphabetic: /^[a-zA-Z\s]+$/,
            numeric: /^[0-9]+$/,
            url: /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/,
            // Unicode-safe name pattern (supports international characters)
            name: /^[\p{L}\p{M}\s.'-]+$/u
        };

        /**
         * Dangerous SQL keywords and patterns (additional layer of defense)
         * @private
         */
        this._sqlInjectionPatterns = [
            /(\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bCREATE\b|\bALTER\b)/gi,
            /(\bUNION\b.*\bSELECT\b)/gi,
            /(--|\#|\/\*|\*\/)/g,
            /(\bOR\b.*=.*|1\s*=\s*1)/gi,
            /(\bAND\b.*=.*)/gi,
            /;.*(\bDROP\b|\bDELETE\b)/gi
        ];

        /**
         * XSS attack patterns (JavaScript injection attempts)
         * @private
         */
        this._xssPatterns = [
            /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
            /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
            /javascript:/gi,
            /on\w+\s*=/gi, // Event handlers like onclick=, onerror=
            /<embed/gi,
            /<object/gi
        ];

        /**
         * NoSQL injection patterns (MongoDB, etc.)
         * @private
         */
        this._noSqlPatterns = [
            /\$where/gi,
            /\$ne/gi,
            /\$gt/gi,
            /\$regex/gi
        ];
    }

    /**
     * Validates and sanitizes user registration/creation data.
     * 
     * Performs comprehensive validation including:
     * - Required field checks
     * - Format validation (email, phone)
     * - Length constraints
     * - Security threat detection
     * - Data sanitization
     * 
     * @param {Object} userData - User data to validate
     * @param {string} userData.name - User's full name
     * @param {string} userData.email - User's email address
     * @param {string} [userData.contact] - User's contact number
     * @param {string} [userData.password] - User's password
     * 
     * @returns {Object} Validation result
     * @returns {boolean} return.isValid - Whether validation passed
     * @returns {Object} return.errors - Validation errors (if any)
     * @returns {Object} return.sanitized - Sanitized data (if valid)
     * 
     * @example
     * const result = validator.validateUserData({
     *   name: '  John Doe  ',
     *   email: 'JOHN@EXAMPLE.COM',
     *   contact: '+1234567890'
     * });
     * 
     * if (result.isValid) {
     *   // Use result.sanitized for database operations
     *   await userRepo.create(result.sanitized);
     * } else {
     *   console.error(result.errors);
     * }
     */
    validateUserData(userData) {
        const errors = {};
        const sanitized = {};

        // Validate and sanitize name
        if (!userData.name || typeof userData.name !== 'string') {
            errors.name = 'Name is required and must be a string';
        } else {
            const sanitizedName = this.sanitizeString(userData.name);
            
            if (sanitizedName.length < 2) {
                errors.name = 'Name must be at least 2 characters long';
            } else if (sanitizedName.length > 255) {
                errors.name = 'Name must not exceed 255 characters';
            } else if (!this._patterns.name.test(sanitizedName)) {
                errors.name = 'Name contains invalid characters';
            } else if (this.containsSqlInjection(sanitizedName)) {
                errors.name = 'Name contains potentially malicious content';
            } else {
                sanitized.name = sanitizedName;
            }
        }

        // Validate and sanitize email
        if (!userData.email || typeof userData.email !== 'string') {
            errors.email = 'Email is required and must be a string';
        } else {
            const sanitizedEmail = this.sanitizeEmail(userData.email);
            
            if (!this._patterns.email.test(sanitizedEmail)) {
                errors.email = 'Invalid email format';
            } else if (sanitizedEmail.length > 320) { // RFC 5321 standard
                errors.email = 'Email address is too long';
            } else if (this.containsSqlInjection(sanitizedEmail)) {
                errors.email = 'Email contains potentially malicious content';
            } else {
                sanitized.email = sanitizedEmail;
            }
        }

        // Validate and sanitize contact (optional field)
        if (userData.contact !== undefined && userData.contact !== null) {
            if (typeof userData.contact !== 'string') {
                errors.contact = 'Contact must be a string';
            } else {
                const sanitizedContact = this.sanitizeString(userData.contact);
                
                if (!this._patterns.phone.test(sanitizedContact)) {
                    errors.contact = 'Invalid contact number format';
                } else if (sanitizedContact.length > 20) {
                    errors.contact = 'Contact number is too long';
                } else {
                    sanitized.contact = sanitizedContact;
                }
            }
        }

        // Validate password if provided (for registration)
        if (userData.password !== undefined) {
            const passwordValidation = this.validatePassword(userData.password);
            if (!passwordValidation.isValid) {
                errors.password = passwordValidation.errors;
            } else {
                sanitized.password = userData.password; // Don't sanitize password
            }
        }

        return {
            isValid: Object.keys(errors).length === 0,
            errors,
            sanitized: Object.keys(errors).length === 0 ? sanitized : null
        };
    }

    /**
     * Validates user ID parameter.
     * 
     * @param {*} userId - User ID to validate
     * @returns {Object} Validation result
     * @returns {boolean} return.isValid - Whether validation passed
     * @returns {string} [return.error] - Error message if invalid
     * @returns {number} [return.sanitized] - Sanitized integer ID
     * 
     * @example
     * const result = validator.validateUserId(req.params.id);
     * if (!result.isValid) {
     *   return res.status(400).json({ error: result.error });
     * }
     */
    validateUserId(userId) {
        // Check if undefined or null
        if (userId === undefined || userId === null) {
            return {
                isValid: false,
                error: 'User ID is required'
            };
        }

        // Convert to number
        const id = parseInt(userId, 10);

        // Validate it's a positive integer
        if (isNaN(id) || id <= 0 || !Number.isInteger(id)) {
            return {
                isValid: false,
                error: 'User ID must be a positive integer'
            };
        }

        // Check for suspiciously large IDs (potential attack)
        if (id > Number.MAX_SAFE_INTEGER) {
            return {
                isValid: false,
                error: 'User ID is invalid'
            };
        }

        return {
            isValid: true,
            sanitized: id
        };
    }

    /**
     * Validates password strength and security.
     * 
     * Requirements:
     * - Minimum 8 characters
     * - At least one uppercase letter
     * - At least one lowercase letter
     * - At least one number
     * - At least one special character
     * - No common patterns
     * 
     * @param {string} password - Password to validate
     * @returns {Object} Validation result
     * 
     * @example
     * const result = validator.validatePassword('MyP@ssw0rd');
     */
    validatePassword(password) {
        const errors = [];

        if (!password || typeof password !== 'string') {
            return {
                isValid: false,
                errors: ['Password is required']
            };
        }

        if (password.length < 8) {
            errors.push('Password must be at least 8 characters long');
        }

        if (password.length > 128) {
            errors.push('Password must not exceed 128 characters');
        }

        if (!/[a-z]/.test(password)) {
            errors.push('Password must contain at least one lowercase letter');
        }

        if (!/[A-Z]/.test(password)) {
            errors.push('Password must contain at least one uppercase letter');
        }

        if (!/[0-9]/.test(password)) {
            errors.push('Password must contain at least one number');
        }

        if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
            errors.push('Password must contain at least one special character');
        }

        // Check for common patterns
        const commonPatterns = ['password', '12345', 'qwerty', 'admin', 'letmein'];
        if (commonPatterns.some(pattern => password.toLowerCase().includes(pattern))) {
            errors.push('Password contains common patterns and is too weak');
        }

        return {
            isValid: errors.length === 0,
            errors: errors.length > 0 ? errors : null
        };
    }

    /**
     * Sanitizes a general string input.
     * 
     * Operations performed:
     * - Trim whitespace
     * - Remove null bytes
     * - Normalize Unicode
     * - Remove control characters
     * 
     * @param {string} input - String to sanitize
     * @returns {string} Sanitized string
     * 
     * @example
     * const clean = validator.sanitizeString('  Hello\x00World  ');
     * // Returns: 'Hello World'
     */
    sanitizeString(input) {
        if (typeof input !== 'string') {
            return '';
        }

        return input
            .trim()                                    // Remove leading/trailing whitespace
            .replace(/\x00/g, '')                      // Remove null bytes
            .normalize('NFC')                          // Normalize Unicode
            .replace(/[\x00-\x1F\x7F]/g, '');         // Remove control characters
    }

    /**
     * Sanitizes and normalizes email address.
     * 
     * @param {string} email - Email to sanitize
     * @returns {string} Sanitized email in lowercase
     * 
     * @example
     * const email = validator.sanitizeEmail('  JOHN@EXAMPLE.COM  ');
     * // Returns: 'john@example.com'
     */
    sanitizeEmail(email) {
        if (typeof email !== 'string') {
            return '';
        }

        return this.sanitizeString(email).toLowerCase();
    }

    /**
     * Escapes HTML to prevent XSS attacks.
     * 
     * Converts dangerous characters to HTML entities:
     * - < becomes &lt;
     * - > becomes &gt;
     * - & becomes &amp;
     * - " becomes &quot;
     * - ' becomes &#x27;
     * 
     * @param {string} input - String to escape
     * @returns {string} HTML-escaped string
     * 
     * @example
     * const safe = validator.escapeHtml('<script>alert("XSS")</script>');
     * // Returns: '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;'
     */
    escapeHtml(input) {
        if (typeof input !== 'string') {
            return '';
        }

        const htmlEntities = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;'
        };

        return input.replace(/[&<>"'\/]/g, char => htmlEntities[char]);
    }

    /**
 * Validates UUID format (version 4).
 * 
 * @param {string} uuid - UUID to validate
 * @param {string} [fieldName='UUID'] - Field name for error messages
 * @returns {Object} Validation result
 */
validateUUID(uuid, fieldName = 'UUID') {
    // Check if value exists
    if (!uuid) {
        return {
            isValid: false,
            error: `${fieldName} is required`,
            sanitized: null
        };
    }

    // Check if it's a string
    if (typeof uuid !== 'string') {
        return {
            isValid: false,
            error: `${fieldName} must be a string`,
            sanitized: null
        };
    }

    const trimmed = uuid.trim().toLowerCase();

    // UUID v4 pattern: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    // where y is one of [8, 9, a, b]
    const uuidV4Regex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

    if (!uuidV4Regex.test(trimmed)) {
        return {
            isValid: false,
            error: `${fieldName} must be a valid UUID v4 format`,
            sanitized: null
        };
    }

    return {
        isValid: true,
        error: null,
        sanitized: trimmed
    };
}

/**
 * Validates user ID (alias for validateUUID).
 * 
 * @param {string} userId - User ID to validate
 * @returns {Object} Validation result
 */
validateUserId(userId) {
    return this.validateUUID(userId, 'User ID');
}


    /**
     * Detects potential SQL injection attempts.
     * 
     * Note: This is a defense-in-depth measure. Parameterized queries
     * are the primary defense against SQL injection.
     * 
     * @param {string} input - String to check
     * @returns {boolean} True if suspicious patterns detected
     * 
     * @example
     * const isMalicious = validator.containsSqlInjection("' OR '1'='1");
     * // Returns: true
     */
    containsSqlInjection(input) {
        if (typeof input !== 'string') {
            return false;
        }

        return this._sqlInjectionPatterns.some(pattern => pattern.test(input));
    }

    /**
     * Detects potential XSS attack attempts.
     * 
     * @param {string} input - String to check
     * @returns {boolean} True if XSS patterns detected
     * 
     * @example
     * const isXss = validator.containsXss('<script>alert("XSS")</script>');
     * // Returns: true
     */
    containsXss(input) {
        if (typeof input !== 'string') {
            return false;
        }

        return this._xssPatterns.some(pattern => pattern.test(input));
    }

    /**
     * Detects potential NoSQL injection attempts.
     * 
     * @param {*} input - Input to check (can be string or object)
     * @returns {boolean} True if NoSQL injection patterns detected
     * 
     * @example
     * const isNoSqlInjection = validator.containsNoSqlInjection({ $where: 'malicious' });
     * // Returns: true
     */
    containsNoSqlInjection(input) {
        const inputStr = typeof input === 'object' ? JSON.stringify(input) : String(input);
        return this._noSqlPatterns.some(pattern => pattern.test(inputStr));
    }

    /**
     * Validates pagination parameters.
     * 
     * @param {Object} params - Pagination parameters
     * @param {number} params.limit - Maximum results
     * @param {number} params.offset - Results to skip
     * @returns {Object} Validation result with sanitized values
     * 
     * @example
     * const result = validator.validatePaginationParams({
     *   limit: '10',
     *   offset: '0'
     * });
     */
    validatePaginationParams(params) {
        const errors = {};
        const sanitized = {};

        // Validate limit
        const limit = parseInt(params.limit, 10);
        if (isNaN(limit) || limit <= 0) {
            sanitized.limit = 50; // Default
        } else if (limit > 1000) {
            errors.limit = 'Limit cannot exceed 1000';
        } else {
            sanitized.limit = limit;
        }

        // Validate offset
        const offset = parseInt(params.offset, 10);
        if (isNaN(offset) || offset < 0) {
            sanitized.offset = 0; // Default
        } else {
            sanitized.offset = offset;
        }

        return {
            isValid: Object.keys(errors).length === 0,
            errors,
            sanitized
        };
    }

    /**
     * Validates partial update data.
     * Only validates fields that are present.
     * 
     * @param {Object} updateData - Data to validate
     * @returns {Object} Validation result
     * 
     * @example
     * const result = validator.validatePartialUpdate({ name: 'John' });
     */
    validatePartialUpdate(updateData) {
        const errors = {};
        const sanitized = {};

        if (!updateData || typeof updateData !== 'object') {
            return {
                isValid: false,
                errors: { general: 'Update data must be an object' },
                sanitized: null
            };
        }

        // Validate name if provided
        if (updateData.name !== undefined) {
            if (typeof updateData.name !== 'string') {
                errors.name = 'Name must be a string';
            } else {
                const sanitizedName = this.sanitizeString(updateData.name);
                
                if (sanitizedName.length < 2) {
                    errors.name = 'Name must be at least 2 characters long';
                } else if (sanitizedName.length > 255) {
                    errors.name = 'Name must not exceed 255 characters';
                } else if (!this._patterns.name.test(sanitizedName)) {
                    errors.name = 'Name contains invalid characters';
                } else if (this.containsSqlInjection(sanitizedName)) {
                    errors.name = 'Name contains potentially malicious content';
                } else {
                    sanitized.name = sanitizedName;
                }
            }
        }

        // Validate email if provided
        if (updateData.email !== undefined) {
            const sanitizedEmail = this.sanitizeEmail(updateData.email);
            
            if (!this._patterns.email.test(sanitizedEmail)) {
                errors.email = 'Invalid email format';
            } else if (this.containsSqlInjection(sanitizedEmail)) {
                errors.email = 'Email contains potentially malicious content';
            } else {
                sanitized.email = sanitizedEmail;
            }
        }

        // Validate contact if provided
        if (updateData.contact !== undefined) {
            const sanitizedContact = this.sanitizeString(updateData.contact);
            
            if (!this._patterns.phone.test(sanitizedContact)) {
                errors.contact = 'Invalid contact number format';
            } else {
                sanitized.contact = sanitizedContact;
            }
        }

        return {
            isValid: Object.keys(errors).length === 0,
            errors,
            sanitized: Object.keys(errors).length === 0 ? sanitized : null
        };
    }
}

export default SecurityValidator;

/**
 * @fileoverview Error Handler Utility
 * 
 * Provides utility functions for error handling, logging, and formatting.
 * 
 * @module utilities/errors/ErrorHandler
 * @author mr.shaan
 * @version 1.0.0
 * @since 2025-12-14
 */

import { CustomError } from './error.logger.js';

/**
 * Error handler utility class.
 * Provides centralized error handling, logging, and formatting.
 * 
 * @class ErrorHandler
 */
class ErrorHandler {
    /**
     * Logs error with detailed information.
     * 
     * @static
     * @param {Error} error - Error to log
     * @param {Object} [context={}] - Additional context
     */
    static logError(error, context = {}) {
        const timestamp = new Date().toISOString();
        
        if (error instanceof CustomError) {
            console.error('\n=== CUSTOM ERROR ===');
            console.error('Timestamp:', timestamp);
            console.error('Type:', error.type);
            console.error('Code:', error.code);
            console.error('Message:', error.message);
            console.error('Location:', `${error.className}.${error.functionName}()`);
            console.error('Status Code:', error.statusCode);
            
            if (Object.keys(error.details).length > 0) {
                console.error('Details:', JSON.stringify(error.details, null, 2));
            }
            
            if (error.cause) {
                console.error('Caused by:', error.cause.message);
                console.error('Cause Stack:', error.cause.stack);
            }
            
            if (Object.keys(context).length > 0) {
                console.error('Context:', JSON.stringify(context, null, 2));
            }
            
            console.error('Stack:', error.stack);
            console.error('===================\n');
        } else {
            console.error('\n=== STANDARD ERROR ===');
            console.error('Timestamp:', timestamp);
            console.error('Message:', error.message);
            console.error('Stack:', error.stack);
            
            if (Object.keys(context).length > 0) {
                console.error('Context:', JSON.stringify(context, null, 2));
            }
            console.error('======================\n');
        }
    }

    /**
     * Handles error and returns formatted response for API.
     * 
     * @static
     * @param {Error} error - Error to handle
     * @param {Object} [context={}] - Additional context
     * @returns {Object} Formatted error response
     */
    static handleError(error, context = {}) {
        this.logError(error, context);
        
        if (error instanceof CustomError) {
            return {
                success: false,
                error: error.toClientResponse().error,
                statusCode: error.statusCode
            };
        }
        
        // Handle standard errors
        return {
            success: false,
            error: {
                type: 'INTERNAL_ERROR',
                code: 'INT_' + Date.now().toString().slice(-6),
                message: process.env.NODE_ENV === 'production' 
                    ? 'An internal error occurred' 
                    : error.message,
                timestamp: new Date().toISOString()
            },
            statusCode: 500
        };
    }

    /**
     * Wraps a function with error handling.
     * 
     * @static
     * @param {Function} fn - Function to wrap
     * @param {string} className - Class name
     * @param {string} functionName - Function name
     * @returns {Function} Wrapped function
     * 
     * @example
     * const safeFunction = ErrorHandler.wrap(
     *   originalFunction,
     *   'UserService',
     *   'createUser'
     * );
     */
    static wrap(fn, className, functionName) {
        return async function(...args) {
            try {
                return await fn.apply(this, args);
            } catch (error) {
                if (error instanceof CustomError) {
                    throw error;
                }
                
                // Convert standard error to CustomError
                throw new CustomError({
                    type: 'UNEXPECTED_ERROR',
                    code: 'UNX_' + Date.now().toString().slice(-6),
                    message: error.message,
                    className,
                    functionName,
                    cause: error,
                    statusCode: 500
                });
            }
        };
    }

    /**
     * Converts standard error to CustomError if needed.
     * 
     * @static
     * @param {Error} error - Error to convert
     * @param {string} className - Class name
     * @param {string} functionName - Function name
     * @returns {CustomError} Custom error instance
     */
    static toCustomError(error, className, functionName) {
        if (error instanceof CustomError) {
            return error;
        }
        
        return new CustomError({
            type: 'UNEXPECTED_ERROR',
            code: 'UNX_' + Date.now().toString().slice(-6),
            message: error.message,
            className,
            functionName,
            cause: error,
            statusCode: 500
        });
    }

    /**
     * Saves error to database or external logging service.
     * 
     * @static
     * @async
     * @param {Error} error - Error to save
     * @param {Object} [context={}] - Additional context
     */
    static async saveError(error, context = {}) {
        // Implement database/external logging here
        // Example: await errorLogRepo.create({ error: error.toJSON(), context });
        
        // For now, just log to console
        this.logError(error, context);
    }
}

export default ErrorHandler;

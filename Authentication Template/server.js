/**
 * @fileoverview Server Entry Point
 * 
 * Starts the Express application server with graceful shutdown handling,
 * database connection pooling, and comprehensive error management.
 * 
 * Features:
 * - Environment-based configuration
 * - Database connection validation
 * - Graceful shutdown on SIGTERM/SIGINT
 * - Port conflict detection
 * - Production-ready error handling
 * - Health monitoring
 * 
 * @module server
 * @requires ./app
 * @requires ./config/db.config
 * @requires dotenv
 * 
 * @author mr.shaan
 * @version 1.0.0
 * @since 2025-12-15
 */

import dotenv from 'dotenv';
import app from './app.js';
import databaseInstance from './src/configuration/postgres/database.config.js';
import ErrorHandler from './src/utilities/loggers/errorHandler.logger.js';

// Load environment variables
dotenv.config();

/**
 * Server configuration constants
 */
const PORT = parseInt(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const NODE_ENV = process.env.NODE_ENV || 'development';

/**
 * HTTP server instance
 * 
 * @type {import('http').Server}
 */
let server;

/**
 * Server startup flag
 * 
 * @type {boolean}
 */
let isServerRunning = false;

/**
 * Validates environment configuration.
 * 
 * Checks required environment variables and warns about missing optional ones.
 * 
 * @returns {boolean} True if configuration is valid
 */
function validateEnvironment() {
    const requiredVars = [
        'DATABASE_CONNECTION_STRING',
        'JWT_SECRET'
    ];

    const missingVars = requiredVars.filter(varName => !process.env[varName]);

    if (missingVars.length > 0) {
        console.error('❌ Missing required environment variables:');
        missingVars.forEach(varName => {
            console.error(`   - ${varName}`);
        });
        console.error('\n💡 Please create a .env file with all required variables.\n');
        return false;
    }

    return true;
}

/**
 * Tests database connection.
 * 
 * Attempts to connect to PostgreSQL database and validates connection pool.
 * 
 * @async
 * @returns {Promise<boolean>} True if connection is successful
 */
async function testDatabaseConnection() {
    try {
        console.log('🔌 Testing database connection...');
        
        await databaseInstance.testConnection();
        
        const poolStats = databaseInstance.getPoolStats();
        console.log('✅ Database connected successfully');
        console.log(`   - Total connections: ${poolStats.totalCount}`);
        console.log(`   - Idle connections: ${poolStats.idleCount}`);
        console.log(`   - Waiting requests: ${poolStats.waitingCount}`);
        
        return true;
    } catch (error) {
        console.error('❌ Database connection failed:');
        console.error(`   ${error.message}`);
        
        ErrorHandler.logError(error);
        
        return false;
    }
}

/**
 * Starts the HTTP server.
 * 
 * Binds the Express application to the specified port and host.
 * Implements error handling for common startup issues.
 * 
 * @async
 * @returns {Promise<void>}
 */
async function startServer() {
    try {
        // Validate environment
        if (!validateEnvironment()) {
            process.exit(1);
        }

        // Test database connection
        const dbConnected = await testDatabaseConnection();
        if (!dbConnected) {
            console.error('\n❌ Cannot start server without database connection.');
            process.exit(1);
        }

        // Start HTTP server
        server = app.listen(PORT, HOST, () => {
            isServerRunning = true;
            
            console.log('\n' + '='.repeat(60));
            console.log('Server is running!');
            console.log('='.repeat(60));
            console.log(`Environment: ${NODE_ENV}`);
            console.log(`Host: ${HOST}`);
            console.log(`Port: ${PORT}`);
            console.log(`URL: http://localhost:${PORT}`);
            console.log(`Health: http://localhost:${PORT}/api/health`);
            console.log(`Auth API: http://localhost:${PORT}/api/auth`);
            console.log('='.repeat(60) + '\n');
            
            if (NODE_ENV === 'development') {
                console.log('Running in development mode');
                console.log('   - Detailed error messages enabled');
                console.log('   - CORS configured for localhost:3000');
                console.log('   - Hot reload enabled (if using nodemon)\n');
            } else {
                console.log('Running in production mode');
                console.log('   - Secure error messages');
                console.log('   - CORS configured from environment');
                console.log('   - Performance optimizations enabled\n');
            }
        });

        // Handle server errors
        server.on('error', handleServerError);

    } catch (error) {
        console.error('\nFailed to start server:');
        console.error(`   ${error.message}\n`);
        
        ErrorHandler.logError(error);
        
        process.exit(1);
    }
}

/**
 * Handles server startup errors.
 * 
 * Provides detailed error messages for common issues like port conflicts.
 * 
 * @param {Error} error - Server error object
 */
function handleServerError(error) {
    if (error.code === 'EADDRINUSE') {
        console.error('\n Server startup failed:');
        console.error(`   Port ${PORT} is already in use`);
        console.error('\n Solutions:');
        console.error(`   1. Stop the process using port ${PORT}`);
        console.error(`   2. Change the PORT in your .env file`);
        console.error(`   3. Kill the process: lsof -ti:${PORT} | xargs kill -9\n`);
    } else if (error.code === 'EACCES') {
        console.error('\n Server startup failed:');
        console.error(`   Permission denied to bind to port ${PORT}`);
        console.error('\n Solutions:');
        console.error(`   1. Use a port number above 1024`);
        console.error(`   2. Run with elevated permissions (not recommended)\n`);
    } else {
        console.error('\n Server error:');
        console.error(`   ${error.message}\n`);
    }
    
    ErrorHandler.logError(error);
    
    process.exit(1);
}

/**
 * Gracefully shuts down the server.
 * 
 * Closes all active connections and cleans up resources:
 * 1. Stops accepting new connections
 * 2. Waits for existing connections to complete
 * 3. Closes database connection pool
 * 4. Exits process
 * 
 * @async
 * @param {string} signal - Shutdown signal (SIGTERM, SIGINT, etc.)
 * @returns {Promise<void>}
 */
async function gracefulShutdown(signal) {
    console.log(`\n  Received ${signal} signal`);
    console.log(' Initiating graceful shutdown...\n');

    if (!isServerRunning) {
        console.log('Server already stopped\n');
        process.exit(0);
    }

    try {
        // Stop accepting new connections
        if (server) {
            await new Promise((resolve, reject) => {
                server.close((err) => {
                    if (err) {
                        reject(err);
                    } else {
                        console.log('HTTP server closed');
                        resolve();
                    }
                });
            });
        }

        // Close database connections
        await databaseInstance.closePool();
        console.log('Database connections closed');

        console.log('\nGraceful shutdown completed\n');
        
        process.exit(0);

    } catch (error) {
        console.error('\nError during shutdown:');
        console.error(`   ${error.message}\n`);
        
        ErrorHandler.logError(error);
        
        // Force exit if graceful shutdown fails
        process.exit(1);
    }
}

/**
 * Handles uncaught exceptions.
 * 
 * Logs the error and initiates graceful shutdown.
 * 
 * @param {Error} error - Uncaught exception
 */
function handleUncaughtException(error) {
    console.error('\n UNCAUGHT EXCEPTION:');
    console.error(`   ${error.message}`);
    console.error(`\nStack trace:\n${error.stack}\n`);
    
    ErrorHandler.logError(error);
    
    gracefulShutdown('UNCAUGHT_EXCEPTION');
}

/**
 * Handles unhandled promise rejections.
 * 
 * Logs the error and initiates graceful shutdown.
 * 
 * @param {Error} reason - Rejection reason
 * @param {Promise} promise - Rejected promise
 */
function handleUnhandledRejection(reason, promise) {
    console.error('\n UNHANDLED PROMISE REJECTION:');
    console.error(`   ${reason}`);
    console.error(`   Promise: ${promise}\n`);
    
    ErrorHandler.logError(reason);
    
    gracefulShutdown('UNHANDLED_REJECTION');
}

// ============================================
// PROCESS EVENT HANDLERS
// ============================================

// Graceful shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Error handlers
process.on('uncaughtException', handleUncaughtException);
process.on('unhandledRejection', handleUnhandledRejection);

// ============================================
// START SERVER
// ============================================

startServer();

// Export for testing
export { server, startServer, gracefulShutdown };
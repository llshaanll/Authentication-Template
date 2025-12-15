/**
 * @fileoverview PostgreSQL Database Connection Pool Manager
 * 
 * This module provides a singleton database connection pool manager for PostgreSQL.
 * It implements optimal connection pooling strategies to maximize query throughput
 * while preventing resource exhaustion and connection bottlenecks.
 * 
 * Key Features:
 * - Dynamic pool sizing based on system resources and expected load
 * - Automatic connection lifecycle management
 * - Transaction support with automatic rollback on error
 * - Query performance monitoring and slow query detection
 * - Graceful shutdown with connection cleanup
 * - Custom error handling with detailed context tracking
 * 
 * @module config/database
 * @requires pg
 * @requires dotenv
 * @requires os
 * 
 * @author mr.shaan
 * @version 1.0.0
 * @since 2025-12-14
 * 
 * @example
 * // Simple query usage
 * import databaseInstance from './config/database.js';
 * const result = await databaseInstance.query('SELECT * FROM users WHERE id = $1', [userId]);
 * 
 * @example
 * // Transaction usage
 * await databaseInstance.transaction(async (client) => {
 *   await client.query('INSERT INTO orders (user_id) VALUES ($1)', [userId]);
 *   await client.query('UPDATE inventory SET quantity = quantity - 1');
 * });
 */


import pkg from 'pg';
const { Pool } = pkg;
import dotenv from 'dotenv';
import os from 'os';
import { DatabaseError, ValidationError } from '../../utilities/loggers/error.logger.js';
import ErrorHandler from '../../utilities/loggers/errorHandler.logger.js';


// Load environment variables from .env file
dotenv.config();


/**
 * Calculates the optimal PostgreSQL connection pool size based on system resources
 * and expected application load characteristics.
 * 
 * The calculation uses the formula:
 * poolSize = min((CPU_CORES * 2) + (CONCURRENCY * AVG_QUERY_TIME / 1000), 100)
 * 
 * This formula balances:
 * - CPU-bound operations (CPU_CORES * 2)
 * - I/O-bound operations (CONCURRENCY * AVG_QUERY_TIME)
 * - PostgreSQL's practical connection limit (~100-200)
 * 
 * @param {number} [expectedConcurrency=100] - Expected number of concurrent requests.
 *                                             Should match your application's typical load.
 * @param {number} [avgQueryTimeMs=50] - Average query execution time in milliseconds.
 *                                       Lower values indicate faster queries and need fewer connections.
 * 
 * @returns {number} Optimal pool size (minimum 10, maximum 100)
 * 
 * @throws {ValidationError} If parameters are invalid
 * 
 * @example
 * // Calculate for high-traffic API with fast queries
 * const poolSize = calculateOptimalPoolSize(500, 30); // Returns adjusted pool size
 * 
 * @example
 * // Calculate for moderate traffic with slower queries
 * const poolSize = calculateOptimalPoolSize(100, 200);
 */
function calculateOptimalPoolSize(expectedConcurrency = 100, avgQueryTimeMs = 50) {
    // Validate input parameters
    if (expectedConcurrency < 1 || avgQueryTimeMs < 1) {
        throw new ValidationError({
            message: 'Invalid pool size calculation parameters',
            className: 'Database',
            functionName: 'calculateOptimalPoolSize',
            details: { 
                expectedConcurrency, 
                avgQueryTimeMs,
                reason: 'Parameters must be positive numbers'
            }
        });
    }

    const cpuCores = os.cpus().length;
    
    // Calculate optimal size using industry-standard formula
    const optimalSize = Math.min(
        Math.ceil((cpuCores * 2) + (expectedConcurrency * avgQueryTimeMs / 1000)),
        100 // PostgreSQL max connections limit to prevent server overload
    );
    
    // Ensure minimum pool size for production stability
    return Math.max(optimalSize, 10); // Minimum 10 for production resilience
}


/**
 * Database Connection Pool Manager
 * 
 * Manages PostgreSQL connection pooling with automatic resource management,
 * query performance monitoring, and transaction support. Implements the
 * singleton pattern to ensure a single pool instance across the application.
 * 
 * @class Database
 * @classdesc Singleton class managing PostgreSQL connection pool lifecycle
 * 
 * @property {Pool} _pool - Internal PostgreSQL connection pool instance
 * 
 * @example
 * // Access singleton instance
 * import databaseInstance from './config/database.js';
 * 
 * // Execute query
 * const users = await databaseInstance.query('SELECT * FROM users');
 * 
 * // Monitor pool health
 * const stats = databaseInstance.getPoolStats();
 * console.log(`Active connections: ${stats.total}, Idle: ${stats.idle}`);
 */
class Database {
    /**
     * Initializes the database connection pool with optimized configuration.
     * 
     * Configuration priorities:
     * 1. Dynamic pool sizing based on system resources
     * 2. Aggressive timeout settings to prevent connection hoarding
     * 3. Environment-specific behavior (development vs production)
     * 4. Comprehensive error handling and monitoring
     * 
     * Environment Variables Required:
     * - DATABASE_CONNECTION_STRING: PostgreSQL connection URI
     * - NODE_ENV: Environment mode (development/production)
     * - APP_NAME: Application identifier for connection tracking
     * - EXPECTED_CONCURRENCY: (Optional) Expected concurrent users
     * - AVG_QUERY_TIME_MS: (Optional) Average query duration
     * 
     * @constructor
     * @throws {ValidationError} If DATABASE_CONNECTION_STRING is not set
     * @throws {DatabaseError} If pool initialization fails
     */
    constructor() {
        // Validate required environment variables
        if (!process.env.DATABASE_CONNECTION_STRING) {
            throw new ValidationError({
                message: 'DATABASE_CONNECTION_STRING environment variable is required',
                className: 'Database',
                functionName: 'constructor',
                details: {
                    missing: 'DATABASE_CONNECTION_STRING',
                    hint: 'Set DATABASE_CONNECTION_STRING in your .env file'
                }
            });
        }

        try {
            // Calculate pool size dynamically based on system capabilities and expected load
            const poolSize = calculateOptimalPoolSize(
                parseInt(process.env.EXPECTED_CONCURRENCY) || 100,  // Default: 100 concurrent users
                parseInt(process.env.AVG_QUERY_TIME_MS) || 50       // Default: 50ms avg query time
            );
            
            /**
             * PostgreSQL connection pool instance
             * @private
             * @type {Pool}
             */
            this._pool = new Pool({
                connectionString: process.env.DATABASE_CONNECTION_STRING,
                
                // Dynamic pool sizing - scales with application load
                max: poolSize,                              // Maximum pool size
                min: Math.ceil(poolSize * 0.25),           // Maintain 25% as warm connections
                
                // Timeout configurations - aggressive settings to prevent connection leaks
                idleTimeoutMillis: 30000,                  // Close idle connections after 30 seconds
                connectionTimeoutMillis: 2000,             // Fail fast if pool is exhausted (2 seconds)
                statement_timeout: 60000,                  // Kill long-running queries after 60 seconds
                
                // Performance and operational settings
                allowExitOnIdle: process.env.NODE_ENV === 'production' ? false : true,  // Keep process alive in production
                application_name: process.env.APP_NAME || 'your_app'  // For PostgreSQL connection tracking
            });


            /**
             * Error event handler for unexpected pool errors.
             * Logs errors using custom error handler but doesn't crash the process.
             * 
             * @listens Pool#error
             * @param {Error} error - The error that occurred
             * @param {Client} client - The client that experienced the error
             */
            this._pool.on('error', (error, client) => {
                const dbError = new DatabaseError({
                    message: 'Unexpected error on idle PostgreSQL client',
                    className: 'Database',
                    functionName: 'pool.on.error',
                    cause: error,
                    details: {
                        clientInfo: client ? 'Client exists' : 'No client',
                        errorType: error.name,
                        errorCode: error.code
                    }
                });
                
                ErrorHandler.logError(dbError);
                // TODO: Integrate with error monitoring service (e.g., Sentry, DataDog)
            });


            /**
             * Connection event handler for tracking new connections.
             * Disabled in production to reduce logging overhead.
             * 
             * @listens Pool#connect
             * @param {Client} client - Newly connected client instance
             */
            if (process.env.NODE_ENV !== 'production') {
                this._pool.on('connect', (client) => {
                    console.log('New client connected to pool');
                    // Useful for debugging connection lifecycle in development
                });
            }


            // Log initialization success with configuration details
            console.log(`Database pool initialized with max: ${poolSize} connections`);

        } catch (error) {
            // Convert to DatabaseError if not already a custom error
            const dbError = ErrorHandler.toCustomError(error, 'Database', 'constructor');
            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }


    /**
     * Gets the underlying PostgreSQL connection pool instance.
     * Use this for direct pool access when custom configuration is needed.
     * 
     * @readonly
     * @returns {Pool} The PostgreSQL connection pool
     * 
     * @example
     * const pool = databaseInstance.pool;
     * pool.on('acquire', () => console.log('Connection acquired'));
     */
    get pool() {
        return this._pool;
    }

    /**
 * Tests the database connection.
 * 
 * Attempts to execute a simple query to verify database connectivity.
 * Useful for health checks and startup validation.
 * 
 * @async
 * @returns {Promise<boolean>} True if connection is successful
 * 
 * @throws {DatabaseError} If connection test fails
 * 
 * @example
 * // Test connection at startup
 * try {
 *   await databaseInstance.testConnection();
 *   console.log('Database connected');
 * } catch (error) {
 *   console.error('Database connection failed');
 *   process.exit(1);
 * }
 * 
 * @example
 * // Health check endpoint
 * app.get('/health', async (req, res) => {
 *   try {
 *     await databaseInstance.testConnection();
 *     res.json({ database: 'connected' });
 *   } catch (error) {
 *     res.status(503).json({ database: 'disconnected' });
 *   }
 * });
 */
async testConnection() {
    try {
        const result = await this._pool.query('SELECT NOW() as current_time, current_database() as database');
        
        console.log('Database connection test successful');
        console.log(`   - Connected to: ${result.rows[0].database}`);
        console.log(`   - Server time: ${result.rows[0].current_time}`);
        
        return true;
    } catch (error) {
        const dbError = new DatabaseError({
            message: 'Database connection test failed',
            className: 'Database',
            functionName: 'testConnection',
            cause: error,
            details: {
                errorCode: error.code,
                errorMessage: error.message,
                hint: 'Check DATABASE_CONNECTION_STRING in .env and ensure PostgreSQL is running'
            }
        });
        
        ErrorHandler.logError(dbError);
        throw dbError;
    }
}

/**
 * Alias for close() method to match server.js naming convention.
 * 
 * @async
 * @returns {Promise<void>}
 * 
 * @example
 * await databaseInstance.closePool();
 */
async closePool() {
    return await this.close();
}



    /**
     * Executes a single SQL query with automatic connection management.
     * 
     * This is the recommended method for one-off queries as it automatically:
     * - Acquires a connection from the pool
     * - Executes the query
     * - Releases the connection back to the pool
     * - Monitors query performance
     * 
     * @async
     * @param {string} text - SQL query string with optional $1, $2... placeholders
     * @param {Array} [params] - Array of values to bind to query placeholders
     * 
     * @returns {Promise<pg.QueryResult>} Query result object with rows and metadata
     * 
     * @throws {ValidationError} If query text is invalid
     * @throws {DatabaseError} If query execution fails or database connection is lost
     * 
     * @example
     * // Parameterized query (prevents SQL injection)
     * const result = await databaseInstance.query(
     *   'SELECT * FROM users WHERE email = $1 AND active = $2',
     *   ['user@example.com', true]
     * );
     * 
     * @example
     * // Simple query without parameters
     * const result = await databaseInstance.query('SELECT COUNT(*) FROM orders');
     * console.log(result.rows[0].count);
     */
    async query(text, params) {
        // Validate query text
        if (!text || typeof text !== 'string' || text.trim().length === 0) {
            throw new ValidationError({
                message: 'Query text must be a non-empty string',
                className: 'Database',
                functionName: 'query',
                details: { 
                    receivedType: typeof text,
                    receivedValue: text
                }
            });
        }

        const start = Date.now();
        try {
            const res = await this._pool.query(text, params);
            const duration = Date.now() - start;
            
            // Monitor and log slow queries for performance optimization
            if (duration > 1000) {
                console.warn('Slow query detected', { 
                    duration, 
                    query: text.substring(0, 100)  // Log first 100 chars to avoid log bloat
                });
                // TODO: Send slow query alerts to monitoring system
            }
            
            return res;
        } catch (error) {
            const dbError = new DatabaseError({
                message: error.message || 'Query execution failed',
                className: 'Database',
                functionName: 'query',
                cause: error,
                details: {
                    query: text.substring(0, 200),  // First 200 chars for context
                    paramsCount: params ? params.length : 0,
                    errorCode: error.code,
                    errorDetail: error.detail,
                    hint: error.hint
                }
            });
            
            ErrorHandler.logError(dbError, { query: text });
            throw dbError;
        }
    }


    /**
     * Acquires a dedicated client connection for manual transaction control.
     * 
     * IMPORTANT: You MUST call client.release() when done to return
     * the connection to the pool. Use try/finally to ensure release.
     * 
     * Consider using the transaction() method instead for automatic cleanup.
     * 
     * @async
     * @returns {Promise<pg.PoolClient>} A dedicated database client
     * 
     * @throws {DatabaseError} If unable to acquire connection (pool exhausted)
     * 
     * @example
     * const client = await databaseInstance.getClient();
     * try {
     *   await client.query('BEGIN');
     *   await client.query('UPDATE accounts SET balance = balance - 100 WHERE id = $1', [1]);
     *   await client.query('UPDATE accounts SET balance = balance + 100 WHERE id = $1', [2]);
     *   await client.query('COMMIT');
     * } catch (error) {
     *   await client.query('ROLLBACK');
     *   throw error;
     * } finally {
     *   client.release();  // CRITICAL: Always release!
     * }
     */
    async getClient() {
        try {
            return await this._pool.connect();
        } catch (error) {
            const dbError = new DatabaseError({
                message: 'Failed to acquire database client from pool',
                className: 'Database',
                functionName: 'getClient',
                cause: error,
                details: {
                    poolStats: this.getPoolStats(),
                    errorCode: error.code,
                    hint: 'Pool may be exhausted. Check pool size and connection leaks.'
                }
            });
            
            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }


    /**
     * Executes a database transaction with automatic commit/rollback handling.
     * 
     * This method provides transaction safety by automatically:
     * - Acquiring a client connection
     * - Starting a transaction (BEGIN)
     * - Executing your callback with the client
     * - Committing on success
     * - Rolling back on error
     * - Releasing the connection in all cases
     * 
     * @async
     * @param {Function} callback - Async function that receives a client and performs queries
     * 
     * @returns {Promise<*>} The return value of the callback function
     * 
     * @throws {ValidationError} If callback is not a function
     * @throws {DatabaseError} If transaction fails (after rollback)
     * 
     * @example
     * // Transfer money between accounts atomically
     * const result = await databaseInstance.transaction(async (client) => {
     *   await client.query(
     *     'UPDATE accounts SET balance = balance - $1 WHERE id = $2',
     *     [100, fromAccountId]
     *   );
     *   await client.query(
     *     'UPDATE accounts SET balance = balance + $1 WHERE id = $2',
     *     [100, toAccountId]
     *   );
     *   return { success: true };
     * });
     * 
     * @example
     * // Bulk insert with transaction safety
     * await databaseInstance.transaction(async (client) => {
     *   for (const user of users) {
     *     await client.query('INSERT INTO users (name, email) VALUES ($1, $2)', [user.name, user.email]);
     *   }
     * });
     */
    async transaction(callback) {
        // Validate callback
        if (typeof callback !== 'function') {
            throw new ValidationError({
                message: 'Transaction callback must be a function',
                className: 'Database',
                functionName: 'transaction',
                details: {
                    receivedType: typeof callback
                }
            });
        }

        const client = await this.getClient();  // This already throws DatabaseError if fails
        
        try {
            await client.query('BEGIN');                   // Start transaction
            const result = await callback(client);         // Execute user operations
            await client.query('COMMIT');                  // Commit if successful
            return result;
        } catch (error) {
            // Attempt rollback
            try {
                await client.query('ROLLBACK');
            } catch (rollbackError) {
                // Log rollback failure but throw original error
                const rollbackDbError = new DatabaseError({
                    message: 'Transaction rollback failed',
                    className: 'Database',
                    functionName: 'transaction',
                    cause: rollbackError,
                    details: {
                        originalError: error.message,
                        rollbackError: rollbackError.message
                    }
                });
                ErrorHandler.logError(rollbackDbError);
            }
            
            // Convert original error to DatabaseError if needed
            const dbError = error instanceof DatabaseError 
                ? error 
                : new DatabaseError({
                    message: 'Transaction failed',
                    className: 'Database',
                    functionName: 'transaction',
                    cause: error,
                    details: {
                        errorMessage: error.message,
                        errorType: error.constructor.name
                    }
                });
            
            ErrorHandler.logError(dbError, { transactionFailed: true });
            throw dbError;
        } finally {
            client.release();                              // Always return connection to pool
        }
    }


    /**
     * Gracefully closes all connections in the pool and shuts down the pool.
     * 
     * This should be called during application shutdown to:
     * - Wait for active queries to complete
     * - Close all idle connections
     * - Prevent new connections from being created
     * - Clean up resources
     * 
     * @async
     * @returns {Promise<void>}
     * 
     * @throws {DatabaseError} If pool closure fails
     * 
     * @example
     * // In your application shutdown handler
     * process.on('SIGTERM', async () => {
     *   console.log('Shutting down gracefully...');
     *   await databaseInstance.close();
     *   process.exit(0);
     * });
     */
    async close() {
        try {
            await this._pool.end();
            console.log('Database pool closed successfully');
        } catch (error) {
            const dbError = new DatabaseError({
                message: 'Failed to close database pool gracefully',
                className: 'Database',
                functionName: 'close',
                cause: error,
                details: {
                    poolStats: this.getPoolStats(),
                    errorCode: error.code
                }
            });
            
            ErrorHandler.logError(dbError);
            throw dbError;
        }
    }


    /**
     * Returns current pool statistics for monitoring and debugging.
     * 
     * Use this to monitor pool health and identify potential issues:
     * - High waiting count: Pool is exhausted, consider increasing max size
     * - Low idle count: Pool is under heavy load
     * - Total approaching max: May need to scale up
     * 
     * @returns {Object} Pool statistics object
     * @returns {number} return.total - Total number of clients in the pool
     * @returns {number} return.idle - Number of clients not currently in use
     * @returns {number} return.waiting - Number of queued requests waiting for a client
     * 
     * @example
     * // Monitor pool health periodically
     * setInterval(() => {
     *   const stats = databaseInstance.getPoolStats();
     *   console.log(`Pool: ${stats.total} total, ${stats.idle} idle, ${stats.waiting} waiting`);
     *   
     *   if (stats.waiting > 10) {
     *     console.warn('Pool exhaustion detected! Consider scaling up.');
     *   }
     * }, 60000); // Every minute
     * 
     * @example
     * // Check pool health in health check endpoint
     * app.get('/health', (req, res) => {
     *   const stats = databaseInstance.getPoolStats();
     *   res.json({ database: { connected: true, ...stats } });
     * });
     */
    getPoolStats() {
        return {
            total: this._pool.totalCount,      // Total connections (active + idle)
            idle: this._pool.idleCount,        // Available connections
            waiting: this._pool.waitingCount   // Requests waiting for connection
        };
    }
}


/**
 * Singleton instance of the Database class.
 * Import and use this instance throughout your application to ensure
 * a single connection pool is shared across all modules.
 * 
 * @type {Database}
 * @constant
 * 
 * @example
 * import databaseInstance from './config/database.js';
 * const users = await databaseInstance.query('SELECT * FROM users');
 */
const databaseInstance = new Database();


// Export singleton instance as default export
export default databaseInstance;


/**
 * Direct access to the underlying PostgreSQL connection pool.
 * Provided for backward compatibility and advanced use cases.
 * 
 * @type {Pool}
 * @constant
 * 
 * @example
 * import { pool } from './config/database.js';
 * const result = await pool.query('SELECT NOW()');
 */
export const pool = databaseInstance.pool;

/**
 * @class AuthService
 * @description Handles all authentication-related API calls
 * 
 * SOLID Principles:
 * - Single Responsibility: Only auth operations
 * - Interface Segregation: Specific methods for each auth action
 * - Dependency Inversion: Depends on ApiClient abstraction
 */
import ApiClient from './ApiClient';
import TokenManager from '../utils/TokenManager';

class AuthService {
  constructor() {
    this.apiClient = ApiClient;
  }

  /**
   * Register a new user
   * @param {Object} userData - User registration data
   * @returns {Promise<Object>} Registration response
   */
  async register(userData) {
    try {
      const response = await this.apiClient.post('/auth/register', userData);
      return response.data;
    } catch (error) {
      throw this._handleError(error);
    }
  }

  /**
   * Login user
   * @param {Object} credentials - Email and password
   * @returns {Promise<Object>} Login response with token
   */
  async login(credentials) {
    try {
      const response = await this.apiClient.post('/auth/login', credentials);
      const { token, user } = response.data.data;
      
      // Save auth data
      TokenManager.saveAuthData(token, user);
      
      return response.data;
    } catch (error) {
      throw this._handleError(error);
    }
  }

  /**
   * Logout user
   * @returns {Promise<void>}
   */
  async logout() {
    try {
      await this.apiClient.post('/auth/logout');
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Always clear local data
      TokenManager.clearAuthData();
    }
  }

  /**
   * Verify current token
   * @returns {Promise<Object>} Verification response
   */
  async verifyToken() {
    try {
      const response = await this.apiClient.get('/auth/verify');
      return response.data;
    } catch (error) {
      TokenManager.clearAuthData();
      throw this._handleError(error);
    }
  }

  /**
   * Get current user from localStorage
   * @returns {Object|null} User object
   */
  getCurrentUser() {
    return TokenManager.getUser();
  }

  /**
   * Check if user is authenticated
   * @returns {boolean}
   */
  isAuthenticated() {
    return TokenManager.isAuthenticated();
  }

  /**
   * Handle API errors
   * @private
   */
  _handleError(error) {
    const message = error.response?.data?.message || error.message || 'An error occurred';
    return new Error(message);
  }
}

export default new AuthService();

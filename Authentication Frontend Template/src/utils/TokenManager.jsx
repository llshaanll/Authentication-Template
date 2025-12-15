/**
 * @class TokenManager
 * @description Manages JWT tokens and session data in localStorage
 * 
 * SOLID Principles:
 * - Single Responsibility: Only handles token/session storage
 * - Open/Closed: Can be extended for sessionStorage or cookies
 */
class TokenManager {
  constructor() {
    this.TOKEN_KEY = 'auth_token';
    this.USER_KEY = 'auth_user';
    this.SESSION_KEY = 'auth_session';
  }

  /**
   * Saves authentication data to localStorage
   * @param {string} token - JWT token
   * @param {Object} user - User object
   * @param {string} sessionId - Session ID
   */
  saveAuthData(token, user, sessionId = null) {
    try {
      localStorage.setItem(this.TOKEN_KEY, token);
      localStorage.setItem(this.USER_KEY, JSON.stringify(user));
      if (sessionId) {
        localStorage.setItem(this.SESSION_KEY, sessionId);
      }
    } catch (error) {
      console.error('Failed to save auth data:', error);
    }
  }

  /**
   * Retrieves JWT token from localStorage
   * @returns {string|null} JWT token or null
   */
  getToken() {
    return localStorage.getItem(this.TOKEN_KEY);
  }

  /**
   * Retrieves user data from localStorage
   * @returns {Object|null} User object or null
   */
  getUser() {
    try {
      const user = localStorage.getItem(this.USER_KEY);
      return user ? JSON.parse(user) : null;
    } catch (error) {
      console.error('Failed to parse user data:', error);
      return null;
    }
  }

  /**
   * Retrieves session ID from localStorage
   * @returns {string|null} Session ID or null
   */
  getSessionId() {
    return localStorage.getItem(this.SESSION_KEY);
  }

  /**
   * Clears all authentication data
   */
  clearAuthData() {
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.USER_KEY);
    localStorage.removeItem(this.SESSION_KEY);
  }

  /**
   * Checks if user is authenticated
   * @returns {boolean} True if token exists
   */
  isAuthenticated() {
    return !!this.getToken();
  }
}

export default new TokenManager();

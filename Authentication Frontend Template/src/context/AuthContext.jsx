/**
 * @file AuthContext.jsx
 * @description Authentication context provider with state management
 */
import React, { createContext, useContext, useState, useEffect } from 'react';
import AuthService from '../services/AuthService';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Initialize auth state on mount
  useEffect(() => {
    initializeAuth();
  }, []);

  /**
   * Initialize authentication state
   */
  const initializeAuth = async () => {
    try {
      if (AuthService.isAuthenticated()) {
        const currentUser = AuthService.getCurrentUser();
        setUser(currentUser);
        
        // Verify token is still valid
        await AuthService.verifyToken();
      }
    } catch (error) {
      console.error('Auth initialization failed:', error);
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  /**
   * Register new user
   */
  const register = async (userData) => {
    try {
      setError(null);
      setLoading(true);
      const response = await AuthService.register(userData);
      return response;
    } catch (error) {
      setError(error.message);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  /**
   * Login user
   */
  const login = async (credentials) => {
    try {
      setError(null);
      setLoading(true);
      const response = await AuthService.login(credentials);
      setUser(response.data.user);
      return response;
    } catch (error) {
      setError(error.message);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  /**
   * Logout user
   */
  const logout = async () => {
    try {
      setLoading(true);
      await AuthService.logout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      setUser(null);
      setLoading(false);
    }
  };

  const value = {
    user,
    loading,
    error,
    register,
    login,
    logout,
    isAuthenticated: !!user,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

/**
 * Custom hook to use auth context
 */
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

/**
 * @file App.jsx
 * @description Main application component with routing
 */
import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import Header from './components/layout/Header';
import LoginForm from './components/auth/LoginForm';
import SignupForm from './components/auth/SignupForm';
import ProtectedRoute from './components/common/ProtectedRoute';

// Dashboard component (placeholder)
const Dashboard = () => (
  <div className="max-w-7xl mx-auto px-4 py-8">
    <h1 className="text-3xl font-bold text-gray-900 mb-4">Dashboard</h1>
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      <div className="card">
        <h3 className="text-lg font-semibold mb-2">Welcome</h3>
        <p className="text-gray-600">You are successfully logged in!</p>
      </div>
    </div>
  </div>
);

// Profile component (placeholder)
const Profile = () => {
  const { user } = useAuth();
  
  return (
    <div className="max-w-3xl mx-auto px-4 py-8">
      <div className="card">
        <h1 className="text-2xl font-bold text-gray-900 mb-6">Profile</h1>
        <div className="space-y-4">
          <div>
            <label className="text-sm font-medium text-gray-700">Name</label>
            <p className="mt-1 text-gray-900">{user?.name}</p>
          </div>
          <div>
            <label className="text-sm font-medium text-gray-700">Email</label>
            <p className="mt-1 text-gray-900">{user?.email}</p>
          </div>
          <div>
            <label className="text-sm font-medium text-gray-700">Contact</label>
            <p className="mt-1 text-gray-900">{user?.contact || 'Not provided'}</p>
          </div>
        </div>
      </div>
    </div>
  );
};

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <div className="min-h-screen bg-gray-50">
          <Header />
          
          <Routes>
            <Route path="/login" element={<LoginForm />} />
            <Route path="/signup" element={<SignupForm />} />
            
            <Route
              path="/dashboard"
              element={
                <ProtectedRoute>
                  <Dashboard />
                </ProtectedRoute>
              }
            />
            
            <Route
              path="/profile"
              element={
                <ProtectedRoute>
                  <Profile />
                </ProtectedRoute>
              }
            />
            
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </div>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;

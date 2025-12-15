/**
 * @fileoverview Reusable Input Field Component
 * 
 * A flexible, accessible form input component with built-in validation error display,
 * optional icons, and consistent styling. Designed to work seamlessly with form
 * state management and validation libraries while maintaining WCAG 2.1 compliance.
 * 
 * Features:
 * - Multiple input types (text, email, password, tel, etc.)
 * - Optional label with required indicator
 * - Icon support for enhanced UX
 * - Error state handling with visual feedback
 * - Accessible form controls with ARIA attributes
 * - Consistent Tailwind CSS styling
 * - Controlled component pattern
 * 
 * Design Patterns:
 * - Controlled component (value/onChange props)
 * - Composition pattern (icon slot)
 * - Error-first validation display
 * - Visual feedback for all states
 * 
 * Accessibility Features:
 * - Semantic HTML (label, input)
 * - ARIA attributes for errors
 * - Required field indicators
 * - Focus visible states
 * - Screen reader announcements
 * - Keyboard navigation support
 * 
 * Styling States:
 * - Default: Standard border and focus ring
 * - Error: Red border and error message
 * - With Icon: Extra left padding
 * - Required: Asterisk indicator
 * 
 * @module components/common/Input
 * @requires react
 * 
 * @author mr.shaan
 * @version 1.0.0
 * @since 2025-12-16
 * 
 * @example
 * // Basic text input
 * <Input
 *   label="Email"
 *   type="email"
 *   name="email"
 *   value={email}
 *   onChange={(e) => setEmail(e.target.value)}
 *   placeholder="john@example.com"
 *   required
 * />
 * 
 * @example
 * // Input with icon and error
 * <Input
 *   label="Password"
 *   type="password"
 *   name="password"
 *   value={password}
 *   onChange={handleChange}
 *   error="Password must be at least 8 characters"
 *   required
 *   icon={<LockIcon />}
 * />
 * 
 * @example
 * // Optional field without label
 * <Input
 *   type="tel"
 *   name="phone"
 *   value={phone}
 *   onChange={handleChange}
 *   placeholder="Phone number (optional)"
 * />
 */

import React from 'react';


/**
 * Input Component
 * 
 * A controlled form input component with comprehensive validation support,
 * accessibility features, and flexible customization options.
 * 
 * Component Structure:
 * - Container div with margin
 * - Optional label with required indicator
 * - Relative container for icon positioning
 * - Optional icon element (positioned absolutely)
 * - Input field with dynamic classes
 * - Optional error message
 * 
 * State Management:
 * This is a controlled component. Parent component must:
 * 1. Maintain value state
 * 2. Provide onChange handler
 * 3. Handle validation and error state
 * 
 * Error Handling:
 * - Visual feedback (red border)
 * - Error message display below input
 * - ARIA attributes for screen readers
 * - Focus ring color changes to red
 * 
 * Icon Integration:
 * - Icons rendered in absolute position
 * - Input padding adjusted automatically
 * - Icon color uses gray-400 for consistency
 * - Icons should be 20x20px (w-5 h-5)
 * 
 * @component
 * @param {Object} props - Component properties
 * @param {string} [props.label] - Label text displayed above input
 * @param {string} [props.type='text'] - HTML input type (text, email, password, etc.)
 * @param {string} props.name - Input name attribute (required for forms)
 * @param {string} props.value - Controlled input value
 * @param {Function} props.onChange - Change event handler
 * @param {string} [props.placeholder] - Placeholder text
 * @param {boolean} [props.required=false] - Whether field is required
 * @param {string|null} [props.error=null] - Error message to display
 * @param {React.ReactNode|null} [props.icon=null] - Icon element to display
 * 
 * @returns {React.ReactElement} Rendered input field with label and error
 * 
 * @example
 * // Email input with validation
 * const [email, setEmail] = useState('');
 * const [error, setError] = useState(null);
 * 
 * const validateEmail = (value) => {
 *   if (!value) return 'Email is required';
 *   if (!/\S+@\S+\.\S+/.test(value)) return 'Invalid email';
 *   return null;
 * };
 * 
 * const handleChange = (e) => {
 *   const value = e.target.value;
 *   setEmail(value);
 *   setError(validateEmail(value));
 * };
 * 
 * <Input
 *   label="Email Address"
 *   type="email"
 *   name="email"
 *   value={email}
 *   onChange={handleChange}
 *   error={error}
 *   required
 * />
 * 
 * @example
 * // Password input with icon
 * <Input
 *   label="Password"
 *   type="password"
 *   name="password"
 *   value={password}
 *   onChange={(e) => setPassword(e.target.value)}
 *   placeholder="Enter your password"
 *   required
 *   icon={
 *     <svg className="w-5 h-5" fill="none" stroke="currentColor">
 *       <path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6..." />
 *     </svg>
 *   }
 * />
 */
const Input = ({ 
  label, 
  type = 'text', 
  name, 
  value, 
  onChange, 
  placeholder, 
  required = false,
  error = null,
  icon = null
}) => {
  /**
   * Generates unique error ID for ARIA describedby attribute
   * @type {string}
   */
  const errorId = error ? `${name}-error` : undefined;
  
  /**
   * Determines if input should have left padding for icon
   * @type {string}
   */
  const iconPadding = icon ? 'pl-10' : '';
  
  /**
   * Determines error state styling classes
   * @type {string}
   */
  const errorClasses = error ? 'border-red-500 focus:ring-red-500' : '';

  return (
    <div className="mb-4">
      {/* Label Element - Optional */}
      {label && (
        <label 
          htmlFor={name} 
          className="block text-sm font-medium text-gray-700 mb-2"
        >
          {label} 
          {/* Required Indicator - Red asterisk */}
          {required && (
            <span 
              className="text-red-500" 
              aria-label="required"
              role="presentation"
            >
              *
            </span>
          )}
        </label>
      )}
      
      {/* Input Container - Relative positioning for icon */}
      <div className="relative">
        {/* Icon Element - Absolute positioned on left */}
        {icon && (
          <div 
            className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400"
            aria-hidden="true"
            role="presentation"
          >
            {icon}
          </div>
        )}
        
        {/* Input Field */}
        <input
          id={name}
          type={type}
          name={name}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          required={required}
          className={`input-field ${iconPadding} ${errorClasses}`}
          aria-invalid={error ? 'true' : 'false'}
          aria-describedby={errorId}
          aria-required={required}
        />
      </div>
      
      {/* Error Message - Displayed below input when error exists */}
      {error && (
        <p 
          id={errorId}
          className="mt-1 text-sm text-red-600"
          role="alert"
          aria-live="polite"
        >
          {error}
        </p>
      )}
    </div>
  );
};


export default Input;

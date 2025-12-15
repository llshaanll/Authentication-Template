This repository contains a full‑stack authentication template (backend + frontend) that you can plug into any project with minimal changes.

Overview
Backend: Node.js + Express + PostgreSQL + JWT + sessions
Frontend: React + Vite + Tailwind CSS + React Router + Auth Context
Architecture: SOLID, OOP‑style services, layered (routes → middleware → controllers → services → repositories)
Features:

Register / Login / Logout / Logout all devices
JWT access token + session tracking in DB
Protected routes (API + React router)
Centralized error handling & logging
CORS configured for local dev (backend 3000, frontend 5173)
Repository layout (monorepo style):

 
text
.
├── backend/ # Express API (Authentication Template)
│ ├── src/
│ ├── app.js
│ ├── server.js
│ ├── package.json
│ └── .env.example
├── frontend/ # React app (Authentication Frontend Template)
│ ├── src/
│ ├── index.html
│ ├── package.json
│ └── .env.example
├── package.json # Root scripts (optional)
├── .gitignore
└── README.md # (this file)


1. Prerequisites
Node.js 18+ (or 20+) and npm
PostgreSQL 13+ running locally or in the cloud
Git (optional, for version control)

2. Backend Setup (backend/)
2.1 Install dependencies
 
bash
cd backend
npm install

2.2 Configure environment variables
Copy the example env file and edit it:

 
bash
cp .env.example .env

Example configuration:

 
text
# Core
NODE_ENV=development
PORT=3000

# PostgreSQL (connection string OR individual fields)
DATABASE_CONNECTION_STRING=postgresql://user:password@localhost:5432/auth_db

# JWT
JWT_SECRET=your-super-secret-jwt-key-CHANGE-ME
JWT_EXPIRES_IN=24h

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:5173

# Optional pool tuning
EXPECTED_CONCURRENCY=100
AVG_QUERY_TIME_MS=50
APP_NAME=auth-backend

2.3 Initialize database
Create your PostgreSQL database and run the schema (adapt names if needed):

 
sql
CREATE DATABASE auth_db;

\c auth_db

-- Users
CREATE TABLE users (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
name VARCHAR(255) NOT NULL,
email VARCHAR(255) UNIQUE NOT NULL,
contact VARCHAR(20),
created_at TIMESTAMP DEFAULT NOW(),
updated_at TIMESTAMP DEFAULT NOW()
);

-- Passwords
CREATE TABLE user_passwords (
id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
password_hash TEXT NOT NULL,
last_updated TIMESTAMP DEFAULT NOW()
);

-- Sessions (JSONB)
CREATE TABLE user_sessions (
id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
sessions JSONB NOT NULL DEFAULT '[]'
);

-- Activity
CREATE TABLE user_activity (
id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
active_status VARCHAR(50) DEFAULT 'logged_out',
last_seen TIMESTAMP DEFAULT NOW()
);

2.4 Run backend
 
bash
npm run dev

Backend will be available at:

API base: http://localhost:3000/api
Health check: http://localhost:3000/api/health
Auth base: http://localhost:3000/api/auth

3. Frontend Setup (frontend/)
3.1 Install dependencies
 
bash
cd frontend
npm install

3.2 Configure environment variables
 
bash
cp .env.example .env

Example:

 
text
VITE_API_URL=http://localhost:3000/api

3.3 Run frontend
 
bash
npm run dev

Frontend will be available at: http://localhost:5173


4. How the Authentication Flow Works
4.1 Backend flow
Register

POST /api/auth/register
Validates input, creates users, user_passwords, and user_activity records.
Login

POST /api/auth/login
Verifies credentials, issues a JWT, saves session info in user_sessions, and may set a cookie.
Verify token/session

GET /api/auth/verify
Middleware validates Authorization: Bearer <token> + session state.
Logout (current device)

POST /api/auth/logout
Invalidates current session in DB, clears cookie if used.
Logout all devices

POST /api/auth/logout/all
Clears all active sessions for that user.
Change password

PUT /api/auth/password
Updates user_passwords, invalidates sessions if implemented that way.
Core layers:

Routes: define endpoints (src/routes/authentication.route.js)
Middlewares: CORS, auth guard (verifyAuth), error handler
Controllers: map HTTP ↔ service methods
Services: business logic (authentication, session activity, user management)
Repositories: SQL queries using the pooled DB client
4.2 Frontend flow
Uses AuthContext + localStorage to store:

token
user info
ApiClient (Axios wrapper) automatically:

sends Authorization: Bearer <token> header
attaches withCredentials: true for cookies / sessions
ProtectedRoute wraps routes that require an authenticated user
Header shows:

Sign In / Sign Up for guests
Profile + Logout dropdown for authenticated users
Main screens:

/login – login form
/signup – registration
/dashboard – sample protected page
/profile – shows logged‑in user data

5. Using This Template in Your Own Project
5.1 Reuse the backend
Copy backend/ into your project or keep it as a separate service.
Adjust the database schema to match your user model (extra fields, constraints).
Replace or extend controllers/services with project‑specific rules (roles, permissions, etc.).
Integrate additional modules:

Email verification
Password reset
OAuth providers (Google, GitHub, etc.)
5.2 Reuse the frontend
Copy frontend/ into your existing React workspace or mount it under a route (e.g. /auth).
Wire AuthProvider at the root of your app:

 
jsx
import { AuthProvider } from './context/AuthContext';

ReactDOM.createRoot(document.getElementById('root')).render(
<React.StrictMode>
<AuthProvider>
<App />
</AuthProvider>
</React.StrictMode>
);

Use ProtectedRoute for any page that requires login:

 
jsx
<Route
path="/dashboard"
element={
<ProtectedRoute>
<Dashboard />
</ProtectedRoute>
}
/>

Consume auth state anywhere:

 
jsx
import { useAuth } from '../context/AuthContext';

const MyComponent = () => {
const { user, isAuthenticated, logout } = useAuth();
// ...
};

5.3 Change branding & UI
Update Tailwind palette (primary color, backgrounds, etc.).
Replace logo/text in Header.jsx.
Adapt forms to match your domain (extra fields, validations).

6. CORS & Environment Notes
Backend expects allowed origins in CORS_ALLOWED_ORIGINS, e.g.:

 
text
CORS_ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000

Frontend must point to the correct API base in VITE_API_URL.
When deploying, update both sides (e.g. https://api.yourapp.com and https://app.yourapp.com).

7. Development Scripts (Monorepo Root, Optional)
If you keep a root package.json with helper scripts:

 
json
{
"scripts": {
"install:backend": "cd backend && npm install",
"install:frontend": "cd frontend && npm install",
"install:all": "npm run install:backend && npm run install:frontend",
"dev:backend": "cd backend && npm run dev",
"dev:frontend": "cd frontend && npm run dev",
"dev": "concurrently \"npm run dev:backend\" \"npm run dev:frontend\""
}
}

Usage:

 
bash
# Install everything
npm run install:all

# Run both backend and frontend together
npm run dev


8. Adapting for Production
Use strong, unique JWT_SECRET values and rotate them periodically.
Set NODE_ENV=production and configure proper logging.
Use HTTPS in production and secure cookies (e.g. secure, sameSite=strict).
Use a managed PostgreSQL instance and tune pool settings for your traffic.
Put a reverse proxy (Nginx, Caddy, etc.) in front if needed.

9. License & Attribution
You are free to modify, extend, and integrate this authentication template into your own projects.
Add your preferred license file (MIT, Apache‑2.0, etc.) and update author information as needed.
# JWT Token Flow After OAuth2 GitHub Login

This document explains how JWT tokens are generated and used after successful OAuth2 GitHub authentication.

## Overview

After a user successfully logs in with GitHub OAuth2, they need to obtain a JWT token to access protected API endpoints. The JWT token contains user information and the GitHub access token for making API calls.

## Flow Steps

### 1. OAuth2 GitHub Login
- User visits the application and clicks "Login with GitHub"
- User is redirected to GitHub for authorization
- After successful authorization, GitHub redirects back to the application
- Spring Security handles the OAuth2 flow and creates a session

### 2. JWT Token Generation
After successful OAuth2 login, the frontend should call the JWT endpoint:

```bash
GET /api/auth/jwt
```

**Headers Required:**
- Must be authenticated (OAuth2 session must exist)
- No additional headers needed

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "username": "github-username",
    "name": "User Full Name",
    "avatar_url": "https://avatars.githubusercontent.com/...",
    "email": "user@example.com"
  },
  "message": "JWT token generated successfully"
}
```

### 3. Using JWT Token
Once you have the JWT token, include it in subsequent API requests:

```bash
GET /api/github/profile
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Available Endpoints

### Authentication Endpoints

#### `GET /api/auth/jwt`
- **Purpose**: Generate JWT token for authenticated OAuth2 user
- **Authentication**: Requires OAuth2 session
- **Response**: JWT token with user information

#### `POST /api/auth/validate`
- **Purpose**: Validate JWT token
- **Headers**: `Authorization: Bearer <token>`
- **Response**: Token validity and user information

#### `GET /api/auth/user`
- **Purpose**: Get current user information
- **Authentication**: Requires OAuth2 session
- **Response**: User profile data

#### `GET /api/auth/test`
- **Purpose**: Test OAuth2 authentication status
- **Authentication**: None required
- **Response**: Authentication status and user info if authenticated

### Alternative Token Endpoint

#### `GET /api/token?code=<authorization_code>`
- **Purpose**: Exchange GitHub authorization code for JWT token
- **Parameters**: `code` - GitHub authorization code
- **Response**: JWT token
- **Note**: This is an alternative flow that doesn't require OAuth2 session

## Error Handling

### Common Error Responses

#### 401 Unauthorized
```json
{
  "error": "User not authenticated",
  "message": "Please login with GitHub first"
}
```

#### 400 Bad Request
```json
{
  "error": "GitHub username not found",
  "message": "Invalid user data"
}
```

#### 500 Internal Server Error
```json
{
  "error": "Token generation failed",
  "message": "Internal server error"
}
```

## Frontend Integration

### React/TypeScript Example

```typescript
// After successful OAuth2 redirect
const getJwtToken = async () => {
  try {
    const response = await fetch('/api/auth/jwt', {
      method: 'GET',
      credentials: 'include', // Important for OAuth2 session
    });
    
    if (response.ok) {
      const data = await response.json();
      localStorage.setItem('jwt_token', data.token);
      return data;
    } else {
      throw new Error('Failed to get JWT token');
    }
  } catch (error) {
    console.error('Error getting JWT token:', error);
  }
};

// Using JWT token for API calls
const makeAuthenticatedRequest = async (url: string) => {
  const token = localStorage.getItem('jwt_token');
  
  const response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });
  
  return response.json();
};
```

## Security Considerations

1. **JWT Token Storage**: Store tokens securely (localStorage for SPA, httpOnly cookies for better security)
2. **Token Expiration**: JWT tokens expire after 24 hours (configurable in `application.properties`)
3. **HTTPS**: Always use HTTPS in production
4. **CORS**: Properly configured CORS for your frontend domain

## Configuration

### JWT Settings (`application.properties`)
```properties
jwt.secret=your-secret-key
jwt.expiration=86400000  # 24 hours in milliseconds
jwt.header=Authorization
jwt.prefix=Bearer
```

### OAuth2 Settings
```properties
spring.security.oauth2.client.registration.github.client-id=your-client-id
spring.security.oauth2.client.registration.github.client-secret=your-client-secret
spring.security.oauth2.client.registration.github.scope=user,repo
```

## Testing

### Test OAuth2 Authentication
```bash
curl http://localhost:8081/api/auth/test
```

### Test JWT Generation (requires OAuth2 session)
```bash
curl -H "Cookie: JSESSIONID=your-session-id" http://localhost:8081/api/auth/jwt
```

### Test JWT Validation
```bash
curl -H "Authorization: Bearer your-jwt-token" http://localhost:8081/api/auth/validate
```

## Troubleshooting

### Common Issues

1. **"User not authenticated"**: Ensure OAuth2 login was successful and session exists
2. **"GitHub access token not found"**: This is a warning, JWT will still be generated
3. **CORS errors**: Check CORS configuration in `SecurityConfig`
4. **Token validation fails**: Check JWT secret and expiration settings

### Debug Steps

1. Check if OAuth2 session exists: `GET /api/auth/test`
2. Verify JWT token format and expiration
3. Check server logs for detailed error messages
4. Ensure all required properties are configured in `application.properties` 
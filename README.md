# GitHub Manager Backend

This is the backend service for the Arceon GitHub Dashboard application.

## Deployment on Render with Docker

### Prerequisites

- A Render account (https://render.com)
- A GitHub account with OAuth app credentials

### Steps to Deploy

1. Fork or clone this repository to your GitHub account
2. Log in to Render and create a new Web Service
3. Connect your GitHub repository
4. Use the following settings:
   - **Name**: arceon-backend (or your preferred name)
   - **Environment**: Docker
   - **Plan**: Free (or choose a paid plan for better performance)

5. Add the following environment variables:
   - `SPRING_PROFILES_ACTIVE`: prod
   - `PORT`: 8080
   - `GITHUB_CLIENT_ID`: Your GitHub OAuth App client ID
   - `GITHUB_CLIENT_SECRET`: Your GitHub OAuth App client secret
   - `BASE_URL`: Your Render app URL (e.g., https://arceon-backend.onrender.com)

6. Click "Create Web Service"

### GitHub OAuth Configuration

After deploying your application on Render:

1. Go to your GitHub Developer Settings > OAuth Apps
2. Create a new OAuth App or use an existing one
3. Set the Homepage URL to your frontend URL (https://arceon.netlify.app)
4. Set the Authorization callback URL to: `https://your-render-app-url.onrender.com/login/oauth2/code/github`
5. Save the changes
6. Copy the Client ID and Client Secret to use as environment variables in Render

### Frontend Configuration

Make sure your frontend application is configured to connect to your Render backend:

1. Update API endpoint URLs in your frontend code to point to your Render backend
2. Update the GitHub OAuth callback handling to work with your Render backend

## Local Development

### Running with Maven

1. Clone the repository
2. Run `./mvnw spring-boot:run`
3. The application will be available at http://localhost:8081

### Running with Docker

1. Clone the repository
2. Build the Docker image: `docker build -t arceon-backend .`
3. Run the container: `docker run -p 8080:8080 arceon-backend`
4. The application will be available at http://localhost:8080

## Environment Variables

For local development, you can use the default values in `application.properties`.
For production, set these environment variables in Render:

- `SPRING_PROFILES_ACTIVE`: prod
- `PORT`: 8080
- `GITHUB_CLIENT_ID`: Your GitHub OAuth App client ID
- `GITHUB_CLIENT_SECRET`: Your GitHub OAuth App client secret
- `BASE_URL`: Your Render app URL

## Frontend Repository

The frontend code is available at: https://github.com/chandru2301/arceon-backend 
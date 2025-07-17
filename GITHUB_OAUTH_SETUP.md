# GitHub OAuth App Setup

To fix the "redirect_uri is not associated with this application" error, you need to update your GitHub OAuth App settings.

## Steps to Update GitHub OAuth App Settings

1. Go to your GitHub account settings
2. Click on "Developer settings" in the left sidebar
3. Click on "OAuth Apps"
4. Find and select your OAuth App for this project
5. Update the following settings:

### Homepage URL
```
https://arceon.netlify.app
```

### Authorization callback URL
```
https://arceon-backend.onrender.com/login/oauth2/code/github
```

6. Click "Update application"

## Verify Environment Variables in Render

Make sure your Render deployment has the following environment variables:

- `GITHUB_CLIENT_ID`: Your GitHub OAuth App client ID
- `GITHUB_CLIENT_SECRET`: Your GitHub OAuth App client secret

## Testing the OAuth Flow

1. Clear your browser cookies and local storage for arceon.netlify.app
2. Visit https://arceon.netlify.app
3. Click "Login with GitHub"
4. You should be redirected to GitHub for authorization
5. After authorization, you should be redirected back to your application

## Troubleshooting

If you continue to see the "redirect_uri is not associated with this application" error:

1. Double-check that the Authorization callback URL in your GitHub OAuth App settings exactly matches the redirect URI in your application
2. Ensure that your application is using the correct Client ID and Client Secret
3. Check the browser console for any errors during the OAuth flow
4. Verify that your backend is correctly configured to handle the OAuth callback 
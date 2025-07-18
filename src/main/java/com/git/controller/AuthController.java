package com.git.controller;

import com.git.security.JwtTokenUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = {"http://localhost:3000", "https://arceon.netlify.app"})
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    /**
     * Generate JWT token for authenticated OAuth2 user
     * This endpoint should be called after successful GitHub OAuth2 login
     */
    @GetMapping("/jwt")
    public ResponseEntity<?> getJwtToken(@AuthenticationPrincipal OAuth2User principal,
                                        OAuth2AuthenticationToken authentication) {
        logger.info("JWT token request received");
        
        if (principal == null) {
            logger.warn("User not authenticated - principal is null");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "User not authenticated", "message", "Please login with GitHub first"));
        }

        if (authentication == null) {
            logger.warn("Authentication token is null");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Authentication token not found", "message", "Please login with GitHub first"));
        }

        try {
            // Get GitHub username
            String username = principal.getAttribute("login");
            if (username == null) {
                logger.error("GitHub username not found in principal attributes");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("error", "GitHub username not found", "message", "Invalid user data"));
            }
            
            logger.info("Generating JWT token for user: {}", username);
            
            // Create claims with user information
            Map<String, Object> claims = new HashMap<>();
            claims.put("name", principal.getAttribute("name"));
            claims.put("avatar_url", principal.getAttribute("avatar_url"));
            claims.put("email", principal.getAttribute("email"));
            claims.put("id", principal.getAttribute("id"));
            claims.put("type", principal.getAttribute("type"));
            claims.put("site_admin", principal.getAttribute("site_admin"));
            
            // Get GitHub access token and add to claims
            try {
                OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                        authentication.getAuthorizedClientRegistrationId(),
                        authentication.getName());

                if (client != null && client.getAccessToken() != null) {
                    String accessToken = client.getAccessToken().getTokenValue();
                    claims.put("github_token", accessToken);
                    logger.info("GitHub access token retrieved successfully");
                } else {
                    logger.warn("GitHub access token not found in authorized client");
                }
            } catch (Exception e) {
                logger.error("Error getting access token: {}", e.getMessage());
                // Continue without access token - JWT will still be generated
            }
            
            // Generate JWT token
            String token = jwtTokenUtil.generateToken(username, claims);
            
            logger.info("JWT token generated successfully for user: {}", username);
            
            // Return structured response
            Map<String, Object> response = new HashMap<>();
            response.put("token", token);
            response.put("user", Map.of(
                "username", username,
                "name", principal.getAttribute("name"),
                "avatar_url", principal.getAttribute("avatar_url"),
                "email", principal.getAttribute("email")
            ));
            response.put("message", "JWT token generated successfully");
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Error generating JWT token: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Token generation failed", "message", "Internal server error"));
        }
    }

    /**
     * Validate JWT token
     */
    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid authorization header", "message", "Bearer token required"));
        }

        String token = authHeader.substring(7);
        
        try {
            String username = jwtTokenUtil.extractUsername(token);
            Date expiration = jwtTokenUtil.extractExpiration(token);
            
            Map<String, Object> response = new HashMap<>();
            response.put("valid", true);
            response.put("username", username);
            response.put("expires_at", expiration);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Token validation failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid token", "message", "Token is invalid or expired"));
        }
    }

    /**
     * Get current user information
     */
    @GetMapping("/user")
    public ResponseEntity<?> getCurrentUser(@AuthenticationPrincipal OAuth2User principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "User not authenticated", "message", "Please login with GitHub first"));
        }

        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("username", principal.getAttribute("login"));
        userInfo.put("name", principal.getAttribute("name"));
        userInfo.put("avatar_url", principal.getAttribute("avatar_url"));
        userInfo.put("email", principal.getAttribute("email"));
        userInfo.put("id", principal.getAttribute("id"));
        userInfo.put("type", principal.getAttribute("type"));
        userInfo.put("site_admin", principal.getAttribute("site_admin"));

        return ResponseEntity.ok(userInfo);
    }

    /**
     * Test endpoint to check OAuth2 authentication status
     */
    @GetMapping("/test")
    public ResponseEntity<?> testAuth(@AuthenticationPrincipal OAuth2User principal,
                                     OAuth2AuthenticationToken authentication) {
        Map<String, Object> response = new HashMap<>();
        
        if (principal == null) {
            response.put("authenticated", false);
            response.put("message", "User not authenticated");
            return ResponseEntity.ok(response);
        }
        
        response.put("authenticated", true);
        response.put("username", principal.getAttribute("login"));
        response.put("name", principal.getAttribute("name"));
        response.put("has_authentication_token", authentication != null);
        
        if (authentication != null) {
            response.put("authorized_client_registration_id", authentication.getAuthorizedClientRegistrationId());
            response.put("name", authentication.getName());
        }
        
        return ResponseEntity.ok(response);
    }
}
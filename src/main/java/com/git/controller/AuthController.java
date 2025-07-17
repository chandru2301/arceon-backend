package com.git.controller;

import com.git.security.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = {"http://localhost:3000", "https://arceon.netlify.app"})
public class AuthController {

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/jwt")
    public ResponseEntity<?> getJwtToken(@AuthenticationPrincipal OAuth2User principal,
                                        OAuth2AuthenticationToken authentication) {
        if (principal == null) {
            return ResponseEntity.status(401).body("User not authenticated");
        }

        // Get GitHub username
        String username = principal.getAttribute("login");
        
        // Create claims with user information
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", principal.getAttribute("name"));
        claims.put("avatar_url", principal.getAttribute("avatar_url"));
        
        // Get GitHub access token and add to claims
        try {
            OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                    authentication.getAuthorizedClientRegistrationId(),
                    authentication.getName());

            if (client != null && client.getAccessToken() != null) {
                claims.put("github_token", client.getAccessToken().getTokenValue());
            }
        } catch (Exception e) {
            System.err.println("Error getting access token: " + e.getMessage());
        }
        
        // Generate JWT token
        String token = jwtTokenUtil.generateToken(username, claims);
        
        return ResponseEntity.ok(Map.of("token", token));
    }
}
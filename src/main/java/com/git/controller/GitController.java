package com.git.controller;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = {"http://localhost:3000", "https://arceon.netlify.app"})
public class GitController {

    @Autowired
    private RestTemplate restTemplate;

    @Value("${github.api.base-url:https://api.github.com}")
    private String githubApiBaseUrl;

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/token")
    public ResponseEntity<?> getToken(OAuth2AuthenticationToken authentication) {
        if (authentication == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not authenticated");
        }

        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(),
                authentication.getName());

        if (client == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
        }

        return ResponseEntity.ok(Collections.singletonMap("token", client.getAccessToken().getTokenValue()));
    }

    // Get current authenticated user
    @GetMapping("/user")
    public ResponseEntity<?> getCurrentUser(@AuthenticationPrincipal OAuth2User principal) {
        if (principal == null) {
            return ResponseEntity.status(401).body("User not authenticated");
        }
        
        return ResponseEntity.ok(principal.getAttributes());
    }

    // Get user's GitHub profile
    @GetMapping("/github/profile")
    public ResponseEntity<?> getGitHubProfile(OAuth2AuthenticationToken authentication) {
        if (authentication == null) {
            return ResponseEntity.status(401).body("User not authenticated");
        }

        String accessToken = getAccessToken(authentication);
        if (accessToken == null) {
            return ResponseEntity.status(401).body("GitHub access token not found");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.set("Accept", "application/vnd.github+json");
            headers.set("User-Agent", "GitHub-Flow-App");

            HttpEntity<String> entity = new HttpEntity<>(headers);
            ResponseEntity<Map> response = restTemplate.exchange(
                githubApiBaseUrl + "/user",
                HttpMethod.GET,
                entity,
                Map.class
            );

            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching GitHub profile: " + e.getMessage());
        }
    }

    // Get user's repositories
    @GetMapping("/github/repositories")
    public ResponseEntity<?> getRepositories(OAuth2AuthenticationToken authentication,
                                           @RequestParam(defaultValue = "30") int per_page,
                                           @RequestParam(defaultValue = "updated") String sort) {
        if (authentication == null) {
            return ResponseEntity.status(401).body("User not authenticated");
        }

        String accessToken = getAccessToken(authentication);
        if (accessToken == null) {
            return ResponseEntity.status(401).body("GitHub access token not found");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.set("Accept", "application/vnd.github+json");
            headers.set("User-Agent", "GitHub-Flow-App");

            HttpEntity<String> entity = new HttpEntity<>(headers);
            ResponseEntity<List> response = restTemplate.exchange(
                githubApiBaseUrl + "/user/repos?per_page=" + per_page + "&sort=" + sort,
                HttpMethod.GET,
                entity,
                List.class
            );

            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching repositories: " + e.getMessage());
        }
    }

    // Get user's pull requests
    @GetMapping("/github/pull-requests")
    public ResponseEntity<?> getPullRequests(OAuth2AuthenticationToken authentication) {
        if (authentication == null) {
            return ResponseEntity.status(401).body("User not authenticated");
        }

        String accessToken = getAccessToken(authentication);
        if (accessToken == null) {
            return ResponseEntity.status(401).body("GitHub access token not found");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.set("Accept", "application/vnd.github+json");
            headers.set("User-Agent", "GitHub-Flow-App");

            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            // Get pull requests from user's repositories
            OAuth2User user = (OAuth2User) authentication.getPrincipal();
            ResponseEntity<Map> response = restTemplate.exchange(
                githubApiBaseUrl + "/search/issues?q=type:pr+author:" + user.getAttribute("login"),
                HttpMethod.GET,
                entity,
                Map.class
            );

            Map<String, Object> result = response.getBody();
            List<Map<String, Object>> pullRequests = (List<Map<String, Object>>) result.get("items");

            return ResponseEntity.ok(pullRequests);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching pull requests: " + e.getMessage());
        }
    }

    // Get user's recent commits
    @GetMapping("/github/commits")
    public ResponseEntity<?> getCommits(OAuth2AuthenticationToken authentication) {
        if (authentication == null) {
            return ResponseEntity.status(401).body("User not authenticated");
        }

        String accessToken = getAccessToken(authentication);
        if (accessToken == null) {
            return ResponseEntity.status(401).body("GitHub access token not found");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.set("Accept", "application/vnd.github+json");
            headers.set("User-Agent", "GitHub-Flow-App");

            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            // Get user's events to find recent commits
            OAuth2User user = (OAuth2User) authentication.getPrincipal();
            ResponseEntity<List> response = restTemplate.exchange(
                githubApiBaseUrl + "/users/" + user.getAttribute("login") + "/events/public",
                HttpMethod.GET,
                entity,
                List.class
            );

            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching commits: " + e.getMessage());
        }
    }

    // Get user's issues
    @GetMapping("/github/user-issues")
    public ResponseEntity<?> getIssues(OAuth2AuthenticationToken authentication) {
        if (authentication == null) {
            return ResponseEntity.status(401).body("User not authenticated");
        }

        String accessToken = getAccessToken(authentication);
        if (accessToken == null) {
            return ResponseEntity.status(401).body("GitHub access token not found");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.set("Accept", "application/vnd.github+json");
            headers.set("User-Agent", "GitHub-Flow-App");

            HttpEntity<String> entity = new HttpEntity<>(headers);
            ResponseEntity<List> response = restTemplate.exchange(
                githubApiBaseUrl + "/issues?filter=all&state=all",
                HttpMethod.GET,
                entity,
                List.class
            );

            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching issues: " + e.getMessage());
        }
    }

    // Get user's activity data
    @GetMapping("/github/activity")
    public ResponseEntity<?> getActivity(OAuth2AuthenticationToken authentication) {
        if (authentication == null) {
            return ResponseEntity.status(401).body("User not authenticated");
        }

        String accessToken = getAccessToken(authentication);
        if (accessToken == null) {
            return ResponseEntity.status(401).body("GitHub access token not found");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.set("Accept", "application/vnd.github+json");
            headers.set("User-Agent", "GitHub-Flow-App");

            HttpEntity<String> entity = new HttpEntity<>(headers);
            OAuth2User user = (OAuth2User) authentication.getPrincipal();
            ResponseEntity<List> response = restTemplate.exchange(
                githubApiBaseUrl + "/users/" + user.getAttribute("login") + "/events",
                HttpMethod.GET,
                entity,
                List.class
            );

            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching activity: " + e.getMessage());
        }
    }

    // Get user's followers
    @GetMapping("/github/followers")
    public ResponseEntity<?> getFollowers(OAuth2AuthenticationToken authentication) {
        if (authentication == null) {
            return ResponseEntity.status(401).body("User not authenticated");
        }

        String accessToken = getAccessToken(authentication);
        if (accessToken == null) {
            return ResponseEntity.status(401).body("GitHub access token not found");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.set("Accept", "application/vnd.github+json");
            headers.set("User-Agent", "GitHub-Flow-App");

            HttpEntity<String> entity = new HttpEntity<>(headers);
            ResponseEntity<List> response = restTemplate.exchange(
                githubApiBaseUrl + "/user/followers",
                HttpMethod.GET,
                entity,
                List.class
            );

            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching followers: " + e.getMessage());
        }
    }

    // Get user's starred repositories
    @GetMapping("/github/starred")
    public ResponseEntity<?> getStarredRepositories(OAuth2AuthenticationToken authentication) {
        if (authentication == null) {
            return ResponseEntity.status(401).body("User not authenticated");
        }

        String accessToken = getAccessToken(authentication);
        if (accessToken == null) {
            return ResponseEntity.status(401).body("GitHub access token not found");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.set("Accept", "application/vnd.github+json");
            headers.set("User-Agent", "GitHub-Flow-App");

            HttpEntity<String> entity = new HttpEntity<>(headers);
            ResponseEntity<List> response = restTemplate.exchange(
                githubApiBaseUrl + "/user/starred",
                HttpMethod.GET,
                entity,
                List.class
            );

            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching starred repositories: " + e.getMessage());
        }
    }

    // Get trending repositories
    @GetMapping("/github/trending")
    public ResponseEntity<?> getTrendingRepositories(OAuth2AuthenticationToken authentication) {
        if (authentication == null) {
            return ResponseEntity.status(401).body("User not authenticated");
        }

        String accessToken = getAccessToken(authentication);
        if (accessToken == null) {
            return ResponseEntity.status(401).body("GitHub access token not found");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.set("Accept", "application/vnd.github+json");
            headers.set("User-Agent", "GitHub-Flow-App");

            HttpEntity<String> entity = new HttpEntity<>(headers);

            ResponseEntity<Map> response = restTemplate.exchange(
                githubApiBaseUrl + "/search/repositories?q=stars:>1000&sort=stars&order=desc",
                HttpMethod.GET,
                entity,
                Map.class
            );

            // Only return the 'items' array from the GitHub response
            Map<String, Object> body = response.getBody();
            Object items = body != null ? body.get("items") : null;

            return ResponseEntity.ok(items);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching trending repositories: " + e.getMessage());
        }
    }
   
        // Helper method to extract access token from OAuth2AuthenticationToken
    private String getAccessToken(OAuth2AuthenticationToken authentication) {
        try {
            OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                    authentication.getAuthorizedClientRegistrationId(),
                    authentication.getName());

            if (client != null && client.getAccessToken() != null) {
                return client.getAccessToken().getTokenValue();
            }
        } catch (Exception e) {
            System.err.println("Error getting access token: " + e.getMessage());
        }
        return null;
    }
    @PostMapping("/github/contributions")
    public ResponseEntity<?> getContributionsGraphQL(OAuth2AuthenticationToken authentication) {
        if (authentication == null) {
            return ResponseEntity.status(401).body("User not authenticated");
        }

        String accessToken = getAccessToken(authentication);
        if (accessToken == null) {
            return ResponseEntity.status(401).body("GitHub access token not found");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("User-Agent", "GitHub-Flow-App");

            OAuth2User user = (OAuth2User) authentication.getPrincipal();
            String login = user.getAttribute("login");

            String graphqlQuery = """
            {
              "query": "query { user(login: \\"%s\\") { contributionsCollection { contributionCalendar { totalContributions weeks { contributionDays { contributionCount date } } } } } }"
            }
            """.formatted(login);

            HttpEntity<String> entity = new HttpEntity<>(graphqlQuery, headers);

            ResponseEntity<String> response = restTemplate.exchange(
                "https://api.github.com/graphql",
                HttpMethod.POST,
                entity,
                String.class
            );

            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching contributions: " + e.getMessage());
        }
    }

@GetMapping("/github/stars")
public ResponseEntity<?> getTotalStars(OAuth2AuthenticationToken authentication) {
    if (authentication == null) {
        return ResponseEntity.status(401).body("User not authenticated");
    }

    String accessToken = getAccessToken(authentication);
    if (accessToken == null) {
        return ResponseEntity.status(401).body("GitHub access token not found");
    }

    try {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.set("Accept", "application/vnd.github+json");
        headers.set("User-Agent", "GitHub-Flow-App");

        OAuth2User user = (OAuth2User) authentication.getPrincipal();
        String login = user.getAttribute("login");

        int totalStars = 0;
        int page = 1;

        while (true) {
            String url = "https://api.github.com/users/" + login + "/repos?per_page=100&page=" + page;
            HttpEntity<String> entity = new HttpEntity<>(headers);
            ResponseEntity<List> response = restTemplate.exchange(url, HttpMethod.GET, entity, List.class);
            List<Map<String, Object>> repos = response.getBody();

            if (repos == null || repos.isEmpty()) break;

            for (Map<String, Object> repo : repos) {
                Integer stars = (Integer) repo.get("stargazers_count");
                if (stars != null) totalStars += stars;
            }

            if (repos.size() < 100) break; // Last page
            page++;
        }

        return ResponseEntity.ok(Map.of("totalStars", totalStars));
    } catch (Exception e) {
        return ResponseEntity.status(500).body("Error fetching stars: " + e.getMessage());
    }
}

@PostMapping("/github/pinned")
public ResponseEntity<?> getPinnedRepos(OAuth2AuthenticationToken authentication) {
    if (authentication == null) {
        return ResponseEntity.status(401).body("User not authenticated");
    }

    String accessToken = getAccessToken(authentication);
    if (accessToken == null) {
        return ResponseEntity.status(401).body("GitHub access token not found");
    }

    try {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("User-Agent", "GitHub-Flow-App");

        OAuth2User user = (OAuth2User) authentication.getPrincipal();
        String login = user.getAttribute("login");

        String graphqlQuery = """
        {
          "query": "query { user(login: \\"%s\\") { pinnedItems(first: 6, types: [REPOSITORY]) { totalCount nodes { ... on Repository { name description stargazerCount url languages(first: 3) { nodes { name color } } } } } } }"
        }
        """.formatted(login);

        HttpEntity<String> entity = new HttpEntity<>(graphqlQuery, headers);

        ResponseEntity<String> response = restTemplate.exchange(
            "https://api.github.com/graphql",
            HttpMethod.POST,
            entity,
            String.class
        );

        return ResponseEntity.ok(response.getBody());
    } catch (Exception e) {
        return ResponseEntity.status(500).body("Error fetching pinned repos: " + e.getMessage());
    }
}

}

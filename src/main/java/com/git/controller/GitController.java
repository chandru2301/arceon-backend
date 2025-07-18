package com.git.controller;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.ArrayList;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.git.security.JwtTokenUtil;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = {"http://localhost:3000", "https://arceon.netlify.app"})
public class GitController {

    @Autowired
    private RestTemplate restTemplate;
    
    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Value("${github.client.id:Ov23liIlROaBzS33BvdP}")
    private String githubClientId;
    @Value("${github.client.secret:c99ea03480d72296a406273e2f4653c6d6db72d7}")
    private String githubClientSecret;
    @Value("${github.redirect.uri:https://arceon.netlify.app/oauth/callback}")
    private String githubRedirectUri;   

    private static final Logger logger = LoggerFactory.getLogger(GitController.class);

    @Value("${github.api.base-url:https://api.github.com}")
    private String githubApiBaseUrl;

    // Cache to track processed OAuth codes to prevent duplicate exchanges
    private final Map<String, Long> processedCodes = new ConcurrentHashMap<>();
    
    @GetMapping("/token")
    public ResponseEntity<?> exchangeCodeForToken(@RequestParam String code) {
        try {
            // Check if this code has already been processed
            if (processedCodes.containsKey(code)) {
                logger.warn("OAuth code already processed: {}", code.substring(0, 6) + "...");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Code already processed");
            }
            
            // Add code to processed cache
            processedCodes.put(code, System.currentTimeMillis());
            
            // Clean up old codes (older than 5 minutes)
            long fiveMinutesAgo = System.currentTimeMillis() - (5 * 60 * 1000);
            processedCodes.entrySet().removeIf(entry -> entry.getValue() < fiveMinutesAgo);
            
            RestTemplate restTemplate = new RestTemplate();
            logger.info("GitHub Client ID: {}", githubClientId);
            logger.info("GitHub Client Secret: {}", githubClientSecret);
            logger.info("GitHub Redirect URI: {}", githubRedirectUri);
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> params = new LinkedMultiValueMap();
            params.add("client_id", githubClientId);
            params.add("client_secret", githubClientSecret);
            params.add("code", code);
            params.add("redirect_uri", githubRedirectUri);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

            ResponseEntity<Map> response = restTemplate.postForEntity(
                    "https://github.com/login/oauth/access_token", request, Map.class);
            logger.info("GitHub Access Token Response: {}", response.getBody());    
            if (response.getStatusCode().is2xxSuccessful()) {
                Map<String, Object> body = response.getBody();
                String accessToken = (String) body.get("access_token");
                logger.info("GitHub Access Token: {}", accessToken);
                // Get user info from GitHub
                HttpHeaders userHeaders = new HttpHeaders();
                userHeaders.setBearerAuth(accessToken);
                HttpEntity<String> userRequest = new HttpEntity<>(userHeaders);
                
                ResponseEntity<Map> userResponse = restTemplate.exchange(
                        "https://api.github.com/user",
                        HttpMethod.GET,
                        userRequest,
                        Map.class);
                logger.info("GitHub User Response: {}", userResponse.getBody());
                if (userResponse.getStatusCode().is2xxSuccessful()) {
                    Map<String, Object> userInfo = userResponse.getBody();
                    String username = (String) userInfo.get("login");
                    
                    // Create JWT token with user info and GitHub access token
                    Map<String, Object> claims = new HashMap<>();
                    claims.put("name", userInfo.get("name"));
                    claims.put("avatar_url", userInfo.get("avatar_url"));
                    claims.put("github_token", accessToken);
                    
                    String jwtToken = jwtTokenUtil.generateToken(username, claims);
                    logger.info("JWT Token: {}", jwtToken);
                    
                    // Return both JWT token and GitHub access token
                    Map<String, Object> responseData = new HashMap<>();
                    responseData.put("token", jwtToken);
                    responseData.put("github_access_token", accessToken);
                    responseData.put("user", userInfo);
                    
                    return ResponseEntity.ok(responseData);
                }
            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token exchange failed");

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("OAuth exchange error");
        }
    }

    // Get current authenticated user
    @GetMapping("/user")
    public ResponseEntity<?> getCurrentUser(HttpServletRequest request) {
        try {
            String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String jwtToken = authHeader.substring(7);
                String username = jwtTokenUtil.extractUsername(jwtToken);
                String githubToken = jwtTokenUtil.extractGitHubToken(jwtToken);
                
                if (username != null && githubToken != null) {
                    // Get user info from GitHub using the token
                    HttpHeaders headers = new HttpHeaders();
                    headers.setBearerAuth(githubToken);
                    headers.set("Accept", "application/vnd.github+json");
                    headers.set("User-Agent", "GitHub-Flow-App");

                    HttpEntity<String> entity = new HttpEntity<>(headers);
                    ResponseEntity<Map> response = restTemplate.exchange(
                        "https://api.github.com/user",
                        HttpMethod.GET,
                        entity,
                        Map.class
                    );
                    return ResponseEntity.ok(response.getBody());
                }
            }
            return ResponseEntity.status(401).body("User not authenticated");
        } catch (Exception e) {
            logger.error("Error getting current user: " + e.getMessage());
            return ResponseEntity.status(401).body("User not authenticated");
        }
    }

    // Get user's GitHub profile
    @GetMapping("/github/profile")
    public ResponseEntity<?> getGitHubProfile(HttpServletRequest request) {
        String accessToken = getGitHubTokenFromJWT(request);
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
            logger.info("GitHub Profile Response: {}", response.getBody());
            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching GitHub profile: " + e.getMessage());
        }
    }

    // Get user's repositories
    @GetMapping("/github/repositories")
    public ResponseEntity<?> getRepositories(HttpServletRequest request,
                                           @RequestParam(defaultValue = "30") int per_page,
                                           @RequestParam(defaultValue = "updated") String sort) {
        String accessToken = getGitHubTokenFromJWT(request);
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
            logger.info("GitHub Repositories Response: {}", response.getBody());
            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching repositories: " + e.getMessage());
        }
    }

    // Get user's pull requests
    @GetMapping("/github/pull-requests")
    public ResponseEntity<?> getPullRequests(HttpServletRequest request) {
        String accessToken = getGitHubTokenFromJWT(request);
        if (accessToken == null) {
            return ResponseEntity.status(401).body("GitHub access token not found");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.set("Accept", "application/vnd.github+json");
            headers.set("User-Agent", "GitHub-Flow-App");

            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            // Get user info from JWT to get the username
            String jwtToken = request.getHeader("Authorization").substring(7);
            String username = jwtTokenUtil.extractUsername(jwtToken);
            
            ResponseEntity<Map> response = restTemplate.exchange(
                githubApiBaseUrl + "/search/issues?q=type:pr+author:" + username,
                HttpMethod.GET,
                entity,
                Map.class
            );
            logger.info("GitHub Pull Requests Response: {}", response.getBody());
            Map<String, Object> result = response.getBody();
            List<Map<String, Object>> pullRequests = (List<Map<String, Object>>) result.get("items");

            return ResponseEntity.ok(pullRequests);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching pull requests: " + e.getMessage());
        }
    }

    // Get user's recent commits
    @GetMapping("/github/commits")
    public ResponseEntity<?> getCommits(HttpServletRequest request) {
        String accessToken = getGitHubTokenFromJWT(request);
        if (accessToken == null) {
            return ResponseEntity.status(401).body("GitHub access token not found");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.set("Accept", "application/vnd.github+json");
            headers.set("User-Agent", "GitHub-Flow-App");

            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            // Get user info from JWT to get the username
            String jwtToken = request.getHeader("Authorization").substring(7);
            String username = jwtTokenUtil.extractUsername(jwtToken);
            
            // Get user's repositories first
            ResponseEntity<List> reposResponse = restTemplate.exchange(
                githubApiBaseUrl + "/users/" + username + "/repos?per_page=100",
                HttpMethod.GET,
                entity,
                List.class
            );
            
            List<Map<String, Object>> repos = reposResponse.getBody();
            List<Map<String, Object>> allCommits = new ArrayList<>();
            
            // Get commits from each repository
            for (Map<String, Object> repo : repos) {
                String repoName = (String) repo.get("name");
                String ownerName = (String) ((Map<String, Object>) repo.get("owner")).get("login");
                
                try {
                    ResponseEntity<List> commitsResponse = restTemplate.exchange(
                        githubApiBaseUrl + "/repos/" + ownerName + "/" + repoName + "/commits?per_page=10",
                        HttpMethod.GET,
                        entity,
                        List.class
                    );
                    
                    List<Map<String, Object>> commits = commitsResponse.getBody();
                    if (commits != null) {
                        allCommits.addAll(commits);
                    }
                } catch (Exception e) {
                    logger.warn("Failed to get commits for repo {}/{}: {}", ownerName, repoName, e.getMessage());
                }
            }
            
            // Sort by commit date and limit to 50 commits
            allCommits.sort((a, b) -> {
                Map<String, Object> commitA = (Map<String, Object>) ((Map<String, Object>) a).get("commit");
                Map<String, Object> authorA = (Map<String, Object>) commitA.get("author");
                String dateA = (String) authorA.get("date");

                Map<String, Object> commitB = (Map<String, Object>) ((Map<String, Object>) b).get("commit");
                Map<String, Object> authorB = (Map<String, Object>) commitB.get("author");
                String dateB = (String) authorB.get("date");

                return dateB.compareTo(dateA); // Most recent first
            });

            
            List<Map<String, Object>> recentCommits = allCommits.stream()
                .limit(50)
                .collect(Collectors.toList());
            
            logger.info("GitHub Commits Response: {} commits", recentCommits.size());
            return ResponseEntity.ok(recentCommits);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching commits: " + e.getMessage());
        }
    }

    // Get user's issues
    @GetMapping("/github/user-issues")
    public ResponseEntity<?> getIssues(HttpServletRequest request) {
        String accessToken = getGitHubTokenFromJWT(request);
        if (accessToken == null) {
            return ResponseEntity.status(401).body("GitHub access token not found");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.set("Accept", "application/vnd.github+json");
            headers.set("User-Agent", "GitHub-Flow-App");

            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            // Get user info from JWT to get the username
            String jwtToken = request.getHeader("Authorization").substring(7);
            String username = jwtTokenUtil.extractUsername(jwtToken);
            
            ResponseEntity<Map> response = restTemplate.exchange(
                githubApiBaseUrl + "/search/issues?q=author:" + username + "+is:issue",
                HttpMethod.GET,
                entity,
                Map.class
            );
            logger.info("GitHub Issues Response: {}", response.getBody());
            Map<String, Object> result = response.getBody();
            List<Map<String, Object>> issues = (List<Map<String, Object>>) result.get("items");

            return ResponseEntity.ok(issues);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching issues: " + e.getMessage());
        }
    }

    // Get user's activity
    @GetMapping("/github/activity")
    public ResponseEntity<?> getActivity(HttpServletRequest request) {
        String accessToken = getGitHubTokenFromJWT(request);
        if (accessToken == null) {
            return ResponseEntity.status(401).body("GitHub access token not found");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.set("Accept", "application/vnd.github+json");
            headers.set("User-Agent", "GitHub-Flow-App");

            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            // Get user info from JWT to get the username
            String jwtToken = request.getHeader("Authorization").substring(7);
            String username = jwtTokenUtil.extractUsername(jwtToken);
            
            ResponseEntity<List> response = restTemplate.exchange(
                githubApiBaseUrl + "/users/" + username + "/events/public",
                HttpMethod.GET,
                entity,
                List.class
            );
            logger.info("GitHub Activity Response: {}", response.getBody());
            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching activity: " + e.getMessage());
        }
    }

    // Get user followers
    @GetMapping("/github/followers")
    public ResponseEntity<?> getFollowers(HttpServletRequest request) {
        String accessToken = getGitHubTokenFromJWT(request);
        if (accessToken == null) {
            return ResponseEntity.status(401).body("GitHub access token not found");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.set("Accept", "application/vnd.github+json");
            headers.set("User-Agent", "GitHub-Flow-App");

            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            // Get user info from JWT to get the username
            String jwtToken = request.getHeader("Authorization").substring(7);
            String username = jwtTokenUtil.extractUsername(jwtToken);
            
            ResponseEntity<List> response = restTemplate.exchange(
                githubApiBaseUrl + "/users/" + username + "/followers",
                HttpMethod.GET,
                entity,
                List.class
            );
            logger.info("GitHub Followers Response: {}", response.getBody());
            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching followers: " + e.getMessage());
        }
    }

    // Get user's starred repositories
    @GetMapping("/github/starred")
    public ResponseEntity<?> getStarredRepositories(HttpServletRequest request) {
        String accessToken = getGitHubTokenFromJWT(request);
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
            logger.info("GitHub Starred Repositories Response: {}", response.getBody());
            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching starred repositories: " + e.getMessage());
        }
    }

    // Get trending repositories
    @GetMapping("/github/trending")
    public ResponseEntity<?> getTrendingRepositories(HttpServletRequest request) {
        String accessToken = getGitHubTokenFromJWT(request);
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
            logger.info("GitHub Trending Repositories Response: {}", response.getBody());
            // Only return the 'items' array from the GitHub response
            Map<String, Object> body = response.getBody();
            Object items = body != null ? body.get("items") : null;

            return ResponseEntity.ok(items);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching trending repositories: " + e.getMessage());
        }
    }
   
        // Helper method to extract access token from OAuth2AuthenticationToken
    private String getGitHubTokenFromJWT(HttpServletRequest request) {
        try {
            String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String jwtToken = authHeader.substring(7);
                return jwtTokenUtil.extractGitHubToken(jwtToken);
            }
        } catch (Exception e) {
            logger.error("Error extracting GitHub token from JWT: " + e.getMessage());
        }
        return null;
    }
    @PostMapping("/github/contributions")
    public ResponseEntity<?> getContributionsGraphQL(HttpServletRequest request) {
        String accessToken = getGitHubTokenFromJWT(request);
        if (accessToken == null) {
            return ResponseEntity.status(401).body("GitHub access token not found");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("User-Agent", "GitHub-Flow-App");

            // Get user info from JWT to get the username
            String jwtToken = request.getHeader("Authorization").substring(7);
            String username = jwtTokenUtil.extractUsername(jwtToken);

            String graphqlQuery = """
            {
              "query": "query { user(login: \\"%s\\") { contributionsCollection { contributionCalendar { totalContributions weeks { contributionDays { contributionCount date } } } } } }"
            }
            """.formatted(username);

            HttpEntity<String> entity = new HttpEntity<>(graphqlQuery, headers);

            ResponseEntity<String> response = restTemplate.exchange(
                "https://api.github.com/graphql",
                HttpMethod.POST,
                entity,
                String.class
            );
            logger.info("GitHub Contributions Response: {}", response.getBody());
            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching contributions: " + e.getMessage());
        }
    }

@GetMapping("/github/stars")
public ResponseEntity<?> getTotalStars(HttpServletRequest request) {
    String accessToken = getGitHubTokenFromJWT(request);
    if (accessToken == null) {
        return ResponseEntity.status(401).body("GitHub access token not found");
    }

    try {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.set("Accept", "application/vnd.github+json");
        headers.set("User-Agent", "GitHub-Flow-App");

        // Get user info from JWT to get the username
        String jwtToken = request.getHeader("Authorization").substring(7);
        String username = jwtTokenUtil.extractUsername(jwtToken);

        int totalStars = 0;
        int page = 1;

        while (true) {
            String url = "https://api.github.com/users/" + username + "/repos?per_page=100&page=" + page;
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
        logger.info("GitHub Total Stars Response: {}", totalStars);
        return ResponseEntity.ok(Map.of("totalStars", totalStars));
    } catch (Exception e) {
        return ResponseEntity.status(500).body("Error fetching stars: " + e.getMessage());
    }
}

@PostMapping("/github/pinned")
public ResponseEntity<?> getPinnedRepos(HttpServletRequest request) {
    String accessToken = getGitHubTokenFromJWT(request);
    if (accessToken == null) {
        return ResponseEntity.status(401).body("GitHub access token not found");
    }

    try {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("User-Agent", "GitHub-Flow-App");

        // Get user info from JWT to get the username
        String jwtToken = request.getHeader("Authorization").substring(7);
        String username = jwtTokenUtil.extractUsername(jwtToken);

        String graphqlQuery = """
        {
          "query": "query { user(login: \\"%s\\") { pinnedItems(first: 6, types: [REPOSITORY]) { totalCount nodes { ... on Repository { name description stargazerCount url languages(first: 3) { nodes { name color } } } } } } }"
        }
        """.formatted(username);

        HttpEntity<String> entity = new HttpEntity<>(graphqlQuery, headers);

        ResponseEntity<String> response = restTemplate.exchange(
            "https://api.github.com/graphql",
            HttpMethod.POST,
            entity,
            String.class
        );
        logger.info("GitHub Pinned Repositories Response: {}", response.getBody());     
        return ResponseEntity.ok(response.getBody());
    } catch (Exception e) {
        return ResponseEntity.status(500).body("Error fetching pinned repos: " + e.getMessage());
    }
}
@GetMapping("/health")
public ResponseEntity<String> healthCheck() {
    logger.info("Health Check Response: Healthy");
        return ResponseEntity.ok("Healthy");
}


}

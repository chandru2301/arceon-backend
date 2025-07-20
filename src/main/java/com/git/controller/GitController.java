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
import org.springframework.web.bind.annotation.PathVariable;

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
    //@Value("${github.redirect.uri:http://localhost:3000/oauth/callback}")
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

    // Get specific user's GitHub profile
    @GetMapping("/github/profile/{username}")
    public ResponseEntity<?> getGitHubProfileByUsername(HttpServletRequest request, @PathVariable String username) {
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
                githubApiBaseUrl + "/users/" + username,
                HttpMethod.GET,
                entity,
                Map.class
            );
            logger.info("GitHub Profile Response for {}: {}", username, response.getBody());
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

@GetMapping("/github/stars/{username}")
public ResponseEntity<?> getTotalStarsByUsername(HttpServletRequest request, @PathVariable String username) {
    String accessToken = getGitHubTokenFromJWT(request);
    if (accessToken == null) {
        return ResponseEntity.status(401).body("GitHub access token not found");
    }

    try {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.set("Accept", "application/vnd.github+json");
        headers.set("User-Agent", "GitHub-Flow-App");

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
        logger.info("GitHub Total Stars Response for {}: {}", username, totalStars);
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

@PostMapping("/github/pinned/{username}")
public ResponseEntity<?> getPinnedReposByUsername(HttpServletRequest request, @PathVariable String username) {
    String accessToken = getGitHubTokenFromJWT(request);
    if (accessToken == null) {
        return ResponseEntity.status(401).body("GitHub access token not found");
    }

    try {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("User-Agent", "GitHub-Flow-App");

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
        logger.info("GitHub Pinned Repositories Response for {}: {}", username, response.getBody());     
        return ResponseEntity.ok(response.getBody());
    } catch (Exception e) {
        return ResponseEntity.status(500).body("Error fetching pinned repos: " + e.getMessage());
    }
}
@GetMapping("/health")
public ResponseEntity<String> healthCheck() {
    return ResponseEntity.ok("GitHub Manager API is running");
}

    // Get recent followers with activity
    @GetMapping("/github/recent-followers")
    public ResponseEntity<?> getRecentFollowers(HttpServletRequest request) {
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
            
            String jwtToken = request.getHeader("Authorization").substring(7);
            String username = jwtTokenUtil.extractUsername(jwtToken);
            
            // Get followers
            ResponseEntity<List> followersResponse = restTemplate.exchange(
                githubApiBaseUrl + "/users/" + username + "/followers?per_page=10",
                HttpMethod.GET,
                entity,
                List.class
            );
            
            List<Map<String, Object>> followers = followersResponse.getBody();
            List<Map<String, Object>> recentFollowers = new ArrayList<>();
            
            if (followers != null) {
                for (int i = 0; i < followers.size(); i++) {
                    Map<String, Object> follower = followers.get(i);
                    Map<String, Object> followerData = new HashMap<>();
                    followerData.put("username", follower.get("login"));
                    followerData.put("name", follower.get("name") != null ? follower.get("name") : follower.get("login"));
                    followerData.put("avatar", follower.get("avatar_url"));
                    followerData.put("action", "started following you");
                    
                    // Simulate different times based on position
                    String[] timeOptions = {"2 hours ago", "5 hours ago", "1 day ago", "2 days ago", "1 week ago"};
                    String time = i < timeOptions.length ? timeOptions[i] : "recently";
                    followerData.put("time", time);
                    
                    recentFollowers.add(followerData);
                }
            }
            
            return ResponseEntity.ok(recentFollowers);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching recent followers: " + e.getMessage());
        }
    }

    // Get starred repository activity
    @GetMapping("/github/starred-activity")
    public ResponseEntity<?> getStarredRepositoryActivity(HttpServletRequest request) {
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
            
            // Get starred repositories
            ResponseEntity<List> starredResponse = restTemplate.exchange(
                githubApiBaseUrl + "/user/starred?per_page=10",
                HttpMethod.GET,
                entity,
                List.class
            );
            
            List<Map<String, Object>> starredRepos = starredResponse.getBody();
            List<Map<String, Object>> activity = new ArrayList<>();
            
            String[] activityTypes = {
                "New release available",
                "Recent commits added",
                "New issues opened",
                "Pull requests merged",
                "Documentation updated"
            };
            
            String[] timeOptions = {"1 hour ago", "3 hours ago", "1 day ago", "2 days ago", "1 week ago"};
            
            if (starredRepos != null) {
                for (int i = 0; i < starredRepos.size(); i++) {
                    Map<String, Object> repo = starredRepos.get(i);
                    String repoName = (String) repo.get("full_name");
                    if (repoName == null) {
                        repoName = (String) repo.get("name");
                    }
                    
                    Map<String, Object> activityData = new HashMap<>();
                    activityData.put("repo", repoName);
                    
                    // Use different activity types based on position
                    String activityType = i < activityTypes.length ? activityTypes[i] : "Repository updated";
                    activityData.put("activity", activityType);
                    
                    // Use different times based on position
                    String time = i < timeOptions.length ? timeOptions[i] : "recently";
                    activityData.put("time", time);
                    activityData.put("type", "star");
                    activity.add(activityData);
                }
            }
            
            return ResponseEntity.ok(activity);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching starred activity: " + e.getMessage());
        }
    }

    // Get community stats
    @GetMapping("/github/community-stats")
    public ResponseEntity<?> getCommunityStats(HttpServletRequest request) {
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
            
            String jwtToken = request.getHeader("Authorization").substring(7);
            String username = jwtTokenUtil.extractUsername(jwtToken);
            
            // Get user profile for stats
            ResponseEntity<Map> profileResponse = restTemplate.exchange(
                githubApiBaseUrl + "/users/" + username,
                HttpMethod.GET,
                entity,
                Map.class
            );
            
            Map<String, Object> profile = profileResponse.getBody();
            Map<String, Object> stats = new HashMap<>();
            
            if (profile != null) {
                stats.put("followers", profile.get("followers"));
                stats.put("following", profile.get("following"));
                stats.put("public_repos", profile.get("public_repos"));
                stats.put("public_gists", profile.get("public_gists"));
            }
            
            return ResponseEntity.ok(stats);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching community stats: " + e.getMessage());
        }
    }

    // Get user achievements and milestones
    @GetMapping("/github/achievements")
    public ResponseEntity<?> getUserAchievements(HttpServletRequest request) {
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
            
            String jwtToken = request.getHeader("Authorization").substring(7);
            String username = jwtTokenUtil.extractUsername(jwtToken);
            
            // Get user profile
            ResponseEntity<Map> profileResponse = restTemplate.exchange(
                githubApiBaseUrl + "/users/" + username,
                HttpMethod.GET,
                entity,
                Map.class
            );
            
            Map<String, Object> profile = profileResponse.getBody();
            
            // Get user repositories for additional stats
            ResponseEntity<List> reposResponse = restTemplate.exchange(
                githubApiBaseUrl + "/users/" + username + "/repos?per_page=100",
                HttpMethod.GET,
                entity,
                List.class
            );
            
            List<Map<String, Object>> repos = reposResponse.getBody();
            
            // Calculate achievements based on real data
            List<Map<String, Object>> achievements = new ArrayList<>();
            
            if (profile != null) {
                Integer publicRepos = (Integer) profile.get("public_repos");
                Integer followers = (Integer) profile.get("followers");
                Integer following = (Integer) profile.get("following");
                
                // First Repository achievement
                Map<String, Object> firstRepo = new HashMap<>();
                firstRepo.put("id", 1);
                firstRepo.put("title", "First Repository");
                firstRepo.put("description", "Created your first GitHub repository");
                firstRepo.put("icon", "GitBranch");
                firstRepo.put("earned", publicRepos != null && publicRepos > 0);
                firstRepo.put("date", "Recently");
                achievements.add(firstRepo);
                
                // 100 Stars achievement
                Map<String, Object> hundredStars = new HashMap<>();
                hundredStars.put("id", 2);
                hundredStars.put("title", "100 Stars");
                hundredStars.put("description", "Received 100 stars across all repositories");
                hundredStars.put("icon", "Star");
                
                // Calculate total stars from repositories
                int totalStars = 0;
                if (repos != null) {
                    for (Map<String, Object> repo : repos) {
                        Integer stars = (Integer) repo.get("stargazers_count");
                        if (stars != null) totalStars += stars;
                    }
                }
                
                hundredStars.put("earned", totalStars >= 100);
                hundredStars.put("progress", Math.min(100, (totalStars * 100) / 100));
                achievements.add(hundredStars);
                
                // Community Builder achievement
                Map<String, Object> communityBuilder = new HashMap<>();
                communityBuilder.put("id", 3);
                communityBuilder.put("title", "Community Builder");
                communityBuilder.put("description", "Gained 50 followers");
                communityBuilder.put("icon", "Users");
                communityBuilder.put("earned", followers != null && followers >= 50);
                communityBuilder.put("progress", followers != null ? Math.min(100, (followers * 100) / 50) : 0);
                achievements.add(communityBuilder);
                
                // Repository Master achievement
                Map<String, Object> repoMaster = new HashMap<>();
                repoMaster.put("id", 4);
                repoMaster.put("title", "Repository Master");
                repoMaster.put("description", "Created 10 public repositories");
                repoMaster.put("icon", "GitBranch");
                repoMaster.put("earned", publicRepos != null && publicRepos >= 10);
                repoMaster.put("progress", publicRepos != null ? Math.min(100, (publicRepos * 100) / 10) : 0);
                achievements.add(repoMaster);
                
                // Star Collector achievement
                Map<String, Object> starCollector = new HashMap<>();
                starCollector.put("id", 5);
                starCollector.put("title", "Star Collector");
                starCollector.put("description", "Received 500 stars across all repositories");
                starCollector.put("icon", "Star");
                starCollector.put("earned", totalStars >= 500);
                starCollector.put("progress", Math.min(100, (totalStars * 100) / 500));
                achievements.add(starCollector);
                
                // Social Butterfly achievement
                Map<String, Object> socialButterfly = new HashMap<>();
                socialButterfly.put("id", 6);
                socialButterfly.put("title", "Social Butterfly");
                socialButterfly.put("description", "Gained 100 followers");
                socialButterfly.put("icon", "Users");
                socialButterfly.put("earned", followers != null && followers >= 100);
                socialButterfly.put("progress", followers != null ? Math.min(100, (followers * 100) / 100) : 0);
                achievements.add(socialButterfly);
                
                // Contributor achievement (simulated)
                Map<String, Object> contributor = new HashMap<>();
                contributor.put("id", 7);
                contributor.put("title", "Contributor");
                contributor.put("description", "Made 365 contributions in a year");
                contributor.put("icon", "Zap");
                contributor.put("earned", false);
                contributor.put("progress", 78); // Simulated progress
                achievements.add(contributor);
            }
            
            return ResponseEntity.ok(achievements);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching achievements: " + e.getMessage());
        }
    }

    // Get user milestones
    @GetMapping("/github/milestones")
    public ResponseEntity<?> getUserMilestones(HttpServletRequest request) {
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
            
            String jwtToken = request.getHeader("Authorization").substring(7);
            String username = jwtTokenUtil.extractUsername(jwtToken);
            
            // Get user profile
            ResponseEntity<Map> profileResponse = restTemplate.exchange(
                githubApiBaseUrl + "/users/" + username,
                HttpMethod.GET,
                entity,
                Map.class
            );
            
            Map<String, Object> profile = profileResponse.getBody();
            
            // Get user repositories
            ResponseEntity<List> reposResponse = restTemplate.exchange(
                githubApiBaseUrl + "/users/" + username + "/repos?per_page=100",
                HttpMethod.GET,
                entity,
                List.class
            );
            
            List<Map<String, Object>> repos = reposResponse.getBody();
            
            // Calculate milestones based on real data
            List<Map<String, Object>> milestones = new ArrayList<>();
            
            if (profile != null && repos != null) {
                Integer publicRepos = (Integer) profile.get("public_repos");
                Integer followers = (Integer) profile.get("followers");
                
                // Calculate total stars
                int totalStars = 0;
                for (Map<String, Object> repo : repos) {
                    Integer stars = (Integer) repo.get("stargazers_count");
                    if (stars != null) totalStars += stars;
                }
                
                // Calculate total contributions
//                int totalContributions = 0;
//                for (Map<String, Object> repo : repos) {
//                    Integer contributions = (Integer) repo.get("contributions");
//                    if (contributions != null) totalContributions += contributions;
//                }
              // GraphQL Query to get total contributions
                 Map<String, Object> queryMap = new HashMap<>();
                 queryMap.put("query", String.format("""
                     query {
                         user(login: "%s") {
                             contributionsCollection {
                                 contributionCalendar {
                                     totalContributions
                                     weeks {
                                         contributionDays {
                                             contributionCount
                                             date
                                         }
                                     }
                                 }
                             }
                         }
                     }
                 """, username));

                 HttpEntity<Map<String, Object>> graphqlRequest = new HttpEntity<>(queryMap, headers);

                 ResponseEntity<Map> contributionsResponse = restTemplate.exchange(
                     githubApiBaseUrl + "/graphql",
                     HttpMethod.POST,
                     graphqlRequest,
                     Map.class
                 );

                 Map<String, Object> contributions = contributionsResponse.getBody();
                 Map<String, Object> data = (Map<String, Object>) contributions.get("data");
                 Map<String, Object> user = (Map<String, Object>) data.get("user");
                 Map<String, Object> collection = (Map<String, Object>) user.get("contributionsCollection");
                 Map<String, Object> calendar = (Map<String, Object>) collection.get("contributionCalendar");

                 // ✅ Get total contributions from GraphQL
                 Integer totalContributions = (Integer) calendar.get("totalContributions");
                 System.out.println("totalContributions: " + totalContributions);

                 // 📌 Add milestone for contributions
                 Map<String, Object> contributionsMilestone = new HashMap<>();
                 contributionsMilestone.put("label", "Total Contributions");
                 contributionsMilestone.put("current", totalContributions != null ? totalContributions : 0);
                 contributionsMilestone.put("target", 1500);
                 contributionsMilestone.put("unit", "contributions");

                 // Optional: Add progress
                 if (totalContributions != null) {
                     double progress = Math.min(100.0, (totalContributions * 100.0) / 1500.0);
                     contributionsMilestone.put("progress", progress);
                 }

                 milestones.add(contributionsMilestone);

                 // 📌 Repositories milestone
                 Map<String, Object> reposMilestone = new HashMap<>();
                 reposMilestone.put("label", "Repositories");
                 reposMilestone.put("current", publicRepos != null ? publicRepos : 0);
                 reposMilestone.put("target", 100);
                 reposMilestone.put("unit", "repos");

                 if (publicRepos != null) {
                     double repoProgress = Math.min(100.0, (publicRepos * 100.0) / 100.0);
                     reposMilestone.put("progress", repoProgress);
                 }

                 milestones.add(reposMilestone);
                
                // Stars milestone
                Map<String, Object> starsMilestone = new HashMap<>();
                starsMilestone.put("label", "Stars Received");
                starsMilestone.put("current", totalStars);
                starsMilestone.put("target", 500);
                starsMilestone.put("unit", "stars");
                milestones.add(starsMilestone);
                
                // Followers milestone
                Map<String, Object> followersMilestone = new HashMap<>();
                followersMilestone.put("label", "Followers");
                followersMilestone.put("current", followers != null ? followers : 0);
                followersMilestone.put("target", 200);
                followersMilestone.put("unit", "followers");
                milestones.add(followersMilestone);
            }
            
            return ResponseEntity.ok(milestones);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching milestones: " + e.getMessage());
        }
    }

    // Get user language statistics
    @GetMapping("/github/languages")
    public ResponseEntity<?> getUserLanguages(HttpServletRequest request) {
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
            
            String jwtToken = request.getHeader("Authorization").substring(7);
            String username = jwtTokenUtil.extractUsername(jwtToken);
            
            // Get user repositories
            ResponseEntity<List> reposResponse = restTemplate.exchange(
                githubApiBaseUrl + "/users/" + username + "/repos?per_page=100",
                HttpMethod.GET,
                entity,
                List.class
            );
            
            List<Map<String, Object>> repos = reposResponse.getBody();
            Map<String, Integer> languageStats = new HashMap<>();
            int totalBytes = 0;
            
            if (repos != null) {
                // Collect language statistics from all repositories
                for (Map<String, Object> repo : repos) {
                    String repoName = (String) repo.get("name");
                    String fullName = (String) repo.get("full_name");
                    
                    // Get languages for this repository
                    ResponseEntity<Map> langResponse = restTemplate.exchange(
                        githubApiBaseUrl + "/repos/" + fullName + "/languages",
                        HttpMethod.GET,
                        entity,
                        Map.class
                    );
                    
                    Map<String, Object> languages = langResponse.getBody();
                    if (languages != null) {
                        for (Map.Entry<String, Object> entry : languages.entrySet()) {
                            String language = entry.getKey();
                            Integer bytes = (Integer) entry.getValue();
                            
                            languageStats.put(language, languageStats.getOrDefault(language, 0) + bytes);
                            totalBytes += bytes;
                        }
                    }
                }
            }
            
            // Convert to chart data format
            List<Map<String, Object>> chartData = new ArrayList<>();
            String[] colors = {
                "#3B82F6", "#10B981", "#F59E0B", "#EF4444", "#8B5CF6",
                "#06B6D4", "#F97316", "#EC4899", "#84CC16", "#6366F1"
            };
            
            int colorIndex = 0;
            for (Map.Entry<String, Integer> entry : languageStats.entrySet()) {
                Map<String, Object> languageData = new HashMap<>();
                languageData.put("name", entry.getKey());
                languageData.put("value", entry.getValue());
                
                // Calculate percentage
                double percentage = totalBytes > 0 ? (entry.getValue() * 100.0) / totalBytes : 0;
                languageData.put("percentage", Math.round(percentage * 100.0) / 100.0);
                languageData.put("color", colors[colorIndex % colors.length]);
                
                chartData.add(languageData);
                colorIndex++;
            }
            
            // Sort by value (descending)
            chartData.sort((a, b) -> Integer.compare((Integer) b.get("value"), (Integer) a.get("value")));
            
            return ResponseEntity.ok(chartData);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching language statistics: " + e.getMessage());
        }
    }

    // Get specific user's language statistics
    @GetMapping("/github/languages/{username}")
    public ResponseEntity<?> getUserLanguagesByUsername(HttpServletRequest request, @PathVariable String username) {
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
            
            // Get user repositories
            ResponseEntity<List> reposResponse = restTemplate.exchange(
                githubApiBaseUrl + "/users/" + username + "/repos?per_page=100",
                HttpMethod.GET,
                entity,
                List.class
            );
            
            List<Map<String, Object>> repos = reposResponse.getBody();
            Map<String, Integer> languageStats = new HashMap<>();
            int totalBytes = 0;
            
            if (repos != null) {
                // Collect language statistics from all repositories
                for (Map<String, Object> repo : repos) {
                    String repoName = (String) repo.get("name");
                    String fullName = (String) repo.get("full_name");
                    
                    // Get languages for this repository
                    ResponseEntity<Map> langResponse = restTemplate.exchange(
                        githubApiBaseUrl + "/repos/" + fullName + "/languages",
                        HttpMethod.GET,
                        entity,
                        Map.class
                    );
                    
                    Map<String, Object> languages = langResponse.getBody();
                    if (languages != null) {
                        for (Map.Entry<String, Object> entry : languages.entrySet()) {
                            String language = entry.getKey();
                            Integer bytes = (Integer) entry.getValue();
                            
                            languageStats.put(language, languageStats.getOrDefault(language, 0) + bytes);
                            totalBytes += bytes;
                        }
                    }
                }
            }
            
            // Convert to chart data format
            List<Map<String, Object>> chartData = new ArrayList<>();
            String[] colors = {
                "#3B82F6", "#10B981", "#F59E0B", "#EF4444", "#8B5CF6",
                "#06B6D4", "#F97316", "#EC4899", "#84CC16", "#6366F1"
            };
            
            int colorIndex = 0;
            for (Map.Entry<String, Integer> entry : languageStats.entrySet()) {
                Map<String, Object> languageData = new HashMap<>();
                languageData.put("name", entry.getKey());
                languageData.put("value", entry.getValue());
                
                // Calculate percentage
                double percentage = totalBytes > 0 ? (entry.getValue() * 100.0) / totalBytes : 0;
                languageData.put("percentage", Math.round(percentage * 100.0) / 100.0);
                languageData.put("color", colors[colorIndex % colors.length]);
                
                chartData.add(languageData);
                colorIndex++;
            }
            
            // Sort by value (descending)
            chartData.sort((a, b) -> Integer.compare((Integer) b.get("value"), (Integer) a.get("value")));
            
            logger.info("GitHub Languages Response for {}: {} languages", username, chartData.size());
            return ResponseEntity.ok(chartData);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching language statistics: " + e.getMessage());
        }
    }
}

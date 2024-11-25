package com.example.demo.controller;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.example.demo.modal.User;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.UserService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api/auth")
public class LoginController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(HttpServletRequest request, HttpServletResponse response) {
        System.out.println("Request: " + request);

        // String refreshToken1 = request.getParameter("refreshToken"); // Assuming it's
        // sent as a request parameter
        // System.out.println("Received refreshToken: " + refreshToken1);

        Cookie[] cookies = request.getCookies();
        String refreshToken = null;

        System.out.println("Checking cookies for refresh token...");
        // Check for refresh token in cookies
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                System.out.println("Cookie name: " + cookie.getName());
                if ("refreshToken".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                    System.out.println("Found refreshToken: " + refreshToken);
                }
            }
        } else {
            System.out.println("No cookies found.");
        }

        Map<String, Object> result = new HashMap<>();
        if (refreshToken != null) {
            // Regenerate access token using refresh token
            System.out.println("Regenerating access token using refresh token...");
            String clientId = extractClientIdFromRefreshToken(refreshToken);
            String accessToken = regenerateAccessToken(refreshToken, clientId);
            // result.put("message", "Regenerated access token");
            result.put("accessToken", accessToken);
            System.out.println("Access token regenerated: " + accessToken);
        } else {
            System.out.println("refreshToken" + request.getHeader("Refresh-Token"));
            String refreshToken1 = request.getHeader("Refresh-Token"); // Change this if needed
            System.out.println("Received refreshToken: " + refreshToken1);
            // No refresh token, extract user info from access token
            System.out.println("No refresh token found, extracting access token from request...");
            String accessToken = extractAccessTokenFromRequest(request);
            System.out.println("Access token extracted: " + accessToken);

            Claims claims = extractClaimsFromAccessToken(accessToken);
            System.out.println("Claims extracted from access token: " + claims);

            // Extract user details
            String username = claims.get("preferred_username", String.class);

            // Safely handle roles extraction
            String roles = claims.get("roles", String.class);
            // String roles = (rolesList != null) ? String.join(",", rolesList) : ""; //
            // Handle null case

            String sid = claims.get("sid", String.class);
            String sub = claims.get("sub", String.class);

            System.out.println(
                    "User details extracted: username = " + username + ", roles = " + roles + ", sid = " + sid);

            // Save user details to the database
            User user = new User();
            user.setSid(sid);
            user.setUsername(username);
            user.setRoles(roles);
            user.setId(sub);
            userRepository.save(user);
            System.out.println("User saved to the database: " + user);

            // Set refresh token in the cookie
            ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", refreshToken1)
                    .httpOnly(true)
                    .path("/")
                    .maxAge(7 * 24 * 60 * 60)
                    .build();
            response.addHeader("Set-Cookie", refreshCookie.toString());
            System.out.println("Refresh token set in cookie.");

            result.put("accessToken", accessToken);
            result.put("username", username);
            result.put("roles", roles);
            result.put("sid", sid);
            System.out.println("Login process"+result);

        }

        System.out.println("Login process completed, returning response."+result);
        return ResponseEntity.ok(result);
    }

    private String extractAccessTokenFromRequest(HttpServletRequest request) {
        System.out.println("Extracting access token from request headers...");
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            String token = bearerToken.substring(7);
            System.out.println("Access token found: " + token);
            return token;
        }
        System.out.println("No access token found in request.");
        return null;
    }

    private Claims extractClaimsFromAccessToken(String accessToken) {
        System.out.println("Extracting claims from access token...");

        // Split the JWT token into its components
        String[] parts = accessToken.split("\\.");
        if (parts.length != 3) {
            System.out.println("Invalid JWT token format.");
            throw new IllegalArgumentException("Invalid JWT token");
        }

        // Decode the payload (the second part of the JWT token)
        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
        System.out.println("Decoded JWT payload: " + payload);

        // Use ObjectMapper to parse the payload
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode payloadNode;
        try {
            payloadNode = objectMapper.readTree(payload);
        } catch (Exception e) {
            System.out.println("Error parsing JWT payload: " + e.getMessage());
            throw new RuntimeException("Failed to parse JWT payload", e);
        }

        // Extract user information from the payload
        String username = payloadNode.get("preferred_username").asText();
        String sid = payloadNode.get("sid").asText();
        String sub = payloadNode.get("sub").asText();
        System.out.println("Extracted user details from JWT: username = " + username + ", sid = " + sid);

        // Extract roles from realm_access
        JsonNode realmAccessNode = payloadNode.get("realm_access");
        String userType = null;
        if (realmAccessNode != null && realmAccessNode.has("roles")) {
            JsonNode rolesNode = realmAccessNode.get("roles");
            if (rolesNode.isArray() && rolesNode.size() > 0) {
                userType = rolesNode.get(0).asText();
                System.out.println("User roles found: " + userType);
            }
        }

        // Create and return claims object
        Claims claims = Jwts.claims();
        claims.put("preferred_username", username);
        claims.put("roles", userType);
        claims.put("sid", sid);
        claims.put("sub", sub);

        System.out.println("Claims object created: " + claims);
        return claims;
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Retrieve refreshToken from cookies
            String refreshToken = null;
            if (request.getCookies() != null) {
                for (Cookie cookie : request.getCookies()) {
                    if (cookie.getName().equals("refreshToken")) {
                        refreshToken = cookie.getValue();
                        break;
                    }
                }
            }

            if (refreshToken == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("No refresh token found in cookies");
            }
            System.out.println("Refresh Token: " + refreshToken);

            // Retrieve client ID and determine if client secret is required
            String clientId = extractClientIdFromRefreshToken(refreshToken);
            System.out.println("Extracted clientId: " + clientId);
    
            if (clientId == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Client ID is missing");
            }

            String clientSecret = getClientSecret(clientId); // Retrieve the client secret, if applicable

            // Prepare the Keycloak logout request
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.set("Content-Type", "application/x-www-form-urlencoded");

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", clientId);
            body.add("refresh_token", refreshToken);

            // Add client secret if the client is not public
            if (clientSecret != null) {
                body.add("client_secret", clientSecret);
            }

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

            // Send the logout request to Keycloak
            ResponseEntity<String> keycloakResponse = restTemplate.exchange(
                    "http://api.kriate.co.in:8346/realms/nishkaiv-bank/protocol/openid-connect/logout",
                    HttpMethod.POST,
                    entity,
                    String.class);

            System.out.println("Keycloak Response Status: " + keycloakResponse.getStatusCode());
            System.out.println("Keycloak Response Body: " + keycloakResponse.getBody());

            if (keycloakResponse.getStatusCode() != HttpStatus.NO_CONTENT) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Failed to logout from Keycloak");
            }

            // Clear the refreshToken cookie
            ResponseCookie clearRefreshToken = ResponseCookie.from("refreshToken", null)
                    .httpOnly(true)
                    .secure(false)
                    .path("/")
                    .maxAge(0)
                    .build();
            response.addHeader("Set-Cookie", clearRefreshToken.toString());

            return ResponseEntity.ok("User logged out");

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    private String extractClientIdFromRefreshToken(String refreshToken) {
        try {
            // Split the JWT token into its components
            String[] parts = refreshToken.split("\\.");
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid JWT token format.");
            }
    
            // Decode the payload (the second part of the JWT token)
            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
            System.out.println("Decoded JWT payload: " + payload);
    
            // Use ObjectMapper to parse the payload
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode payloadNode = objectMapper.readTree(payload);
    
            // Extract client ID (azp) from the payload
            String clientId = payloadNode.get("azp").asText();
            System.out.println("Extracted clientId from refresh token: " + clientId);
    
            return clientId;
    
        } catch (Exception e) {
            System.out.println("Error decoding refresh token: " + e.getMessage());
            return null;
        }
    }

    // Helper method to retrieve client secret based on client_id
    private String getClientSecret(String clientId) {
        // Implement logic to determine if client is public or requires a secret
        // Example: if public clients are known, return null for those clients
        Map<String, String> clientSecrets = Map.of(
                "sector-3", "fs3LlkkyesHYIuW6DF8ASvojIS5KdtfN"
        // Add other clients as needed
        );
        return clientSecrets.getOrDefault(clientId, null); // Return null if no secret exists (public client)
    }

    public String regenerateAccessToken(String refreshToken, String clientId) {

        System.out.println("regenerate function refresh token and clientId"+refreshToken+clientId);

        String url = "http://api.kriate.co.in:8346/realms/nishkaiv-bank/protocol/openid-connect/token";

         RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        body.add("grant_type", "refresh_token");
        body.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(url, requestEntity, String.class);
            if (response.getStatusCode().is2xxSuccessful()) {
                ObjectMapper objectMapper = new ObjectMapper();
                JsonNode jsonNode = objectMapper.readTree(response.getBody());
                return jsonNode.get("access_token").asText();
            } else {
                System.err.println("Failed to regenerate access token: " + response.getStatusCode());
                return null;
            }
        } catch (Exception e) {
            System.err.println("Error during token regeneration: " + e.getMessage());
            return null;
        }
    }

    @GetMapping("/regenerate-accesstoken")
    public ResponseEntity<String> regenerateAccessToken(HttpServletRequest request, HttpServletResponse response) {

        String refreshToken = null;

        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals("refreshToken")) {
                    refreshToken = cookie.getValue();
                    break;
                }
            }
        }
        System.out.println("REFRESH TOKEN:-" + refreshToken);

        if (refreshToken == null) {
            return ResponseEntity.status(400).body("No refresh token found");
        }
        String url = "http://api.kriate.co.in:8346/realms/nishkaiv-bank/protocol/openid-connect/token";
        String clientId =  extractClientIdFromRefreshToken(refreshToken);
        System.out.println("regenerate-accessToken clientId:-"+clientId);

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        body.add("grant_type", "refresh_token");
        body.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(body, headers);
        try {
            ResponseEntity<String> res = restTemplate.postForEntity(url, requestEntity, String.class);
            System.out.println(res);
            if (res.getStatusCode().is2xxSuccessful()) {
                ObjectMapper objectMapper = new ObjectMapper();
                JsonNode jsonNode = objectMapper.readTree(res.getBody());
                String accessToken = jsonNode.get("access_token").asText();
                return ResponseEntity.ok(accessToken);
            } else {

                return ResponseEntity.status(res.getStatusCode()).body("Failed to get access token from keycloak");
            }
        } catch (Exception e) {

            e.printStackTrace();
            return ResponseEntity.status(500).body("Error during getting access token:" +
                    e.getMessage());
        }
    }

    @GetMapping("/check-session")
    public ResponseEntity<Object> checkSession(HttpServletRequest request) {
        try {
            String refreshToken = null;

            // Retrieve the refresh token from cookies
            if (request.getCookies() != null) {
                for (Cookie cookie : request.getCookies()) {
                    if ("refreshToken".equals(cookie.getName())) {
                        refreshToken = cookie.getValue();
                        break;
                    }
                }
            }

            // Check if refresh token is present
            if (refreshToken == null) {
                return ResponseEntity.ok().body("missing token");
            }

            // Decode the JWT manually
            String[] jwtParts = refreshToken.split("\\.");
            if (jwtParts.length < 2) {
                return ResponseEntity.status(400).body("Invalid refresh token format");
            }

            String base64EncodedBody = jwtParts[1];
            String body;

            try {
                body = new String(Base64.getDecoder().decode(base64EncodedBody));
            } catch (IllegalArgumentException e) {
                return ResponseEntity.status(400).body("Failed to decode token");
            }

            // Parse the JWT body to extract information
            ObjectMapper mapper = new ObjectMapper();
            JsonNode payload;
            try {
                payload = mapper.readTree(body);
            } catch (Exception e) {
                return ResponseEntity.status(500).body("Failed to parse token payload");
            }

            // Extracting "sid" and "sub" from the token payload
            String sid = payload.get("sid").asText();
            String sub = payload.get("sub").asText();

            System.out.println("sid" + sid + ":sub:" + sub);
            // Check user existence in the database
            boolean userExists = userService.checkUserExistsBySidAndSub(sid, sub);
            System.out.println("userExists:" + userExists);
            if (!userExists) {
                System.out.println("Returning invalid because user does not exist.");
                return ResponseEntity.ok().body("invalid");
            }
            System.out.println("Returning valid");
            return ResponseEntity.ok().body("valid");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("Internal Server Error");
        }
    }

    @GetMapping("/logged-in-user")
    public ResponseEntity<Object> getLoggedInUser(HttpServletRequest request) {
        try {
            String refreshToken = null;

            // Retrieve the refresh token from cookies
            if (request.getCookies() != null) {
                for (Cookie cookie : request.getCookies()) {
                    if (cookie.getName().equals("refreshToken")) { // Adjust cookie name if needed
                        refreshToken = cookie.getValue();
                        break;
                    }
                }
            }

            if (refreshToken == null) {
                return ResponseEntity.status(404).body("No refresh token");
            }

            // Decode the refresh token (without claims)
            String[] jwtParts = refreshToken.split("\\.");
            if (jwtParts.length < 2) {
                return ResponseEntity.status(400).body("Invalid refresh token format");
            }

            String base64EncodedBody = jwtParts[1];
            String body;
            try {
                body = new String(Base64.getDecoder().decode(base64EncodedBody));
            } catch (IllegalArgumentException e) {
                return ResponseEntity.status(400).body("Failed to decode token");
            }

            // Assuming you use Jackson for JSON processing
            ObjectMapper mapper = new ObjectMapper();
            JsonNode payload = mapper.readTree(body);
            String sub = payload.get("sub").asText();

            // Fetch user from the database
            Optional<User> userOptional = userService.findById(sub); // Adjust method name as needed
            if (!userOptional.isPresent()) {
                return ResponseEntity.status(404).body("No user found");
            }
            System.out.println("logged-in-user"+userOptional.get());

            return ResponseEntity.ok(userOptional.get());

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("Internal Server Error");
        }
    }

}

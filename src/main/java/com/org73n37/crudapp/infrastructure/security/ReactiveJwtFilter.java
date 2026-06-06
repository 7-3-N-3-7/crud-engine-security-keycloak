package com.org73n37.crudapp.infrastructure.security;

import com.org73n37.crudapp.infrastructure.annotations.CrudResource;
import com.org73n37.crudapp.logic.CrudEngine;
import com.org73n37.crudapp.logic.ResourceMetadata;
import tools.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.GrantedAuthority;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * [ARCHITECTURAL OPTIMIZATION]
 * Reactive JWT Authentication WebFilter for Spring WebFlux.
 * Validates OAuth2 JWT signatures, performs dynamic RBAC roles verification,
 * and propagates tenant contexts securely across asynchronous reactive thread hops.
 */
@Component
public class ReactiveJwtFilter implements WebFilter {
    private static final Logger log = LoggerFactory.getLogger(ReactiveJwtFilter.class);

    @Value("${keycloak.jwk-set-uri}")
    private String jwkSetUri;

    @Value("${keycloak.test.public-key:}")
    private String testPublicKeyPem;

    @Autowired
    private CrudEngine crudManager;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private com.org73n37.crudapp.infrastructure.config.AppModeConfig appModeConfig;

    private final Map<String, PublicKey> jwkCache = new ConcurrentHashMap<>();
    private PublicKey parsedTestPublicKey = null;
    private final Object testKeyLock = new Object();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // Skip CORS preflight OPTIONS requests
        if (org.springframework.http.HttpMethod.OPTIONS.equals(exchange.getRequest().getMethod())) {
            return chain.filter(exchange);
        }

        String path = exchange.getRequest().getURI().getPath();

        // Skip metadata public endpoints and health checks
        if (path.equals("/api/metadata") || path.startsWith("/health/") || path.equals("/swagger-ui") || path.equals("/api-docs")) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("[SECURITY EVENT] Action=AUTHENTICATION_FAILURE Path={} Reason=Missing or invalid Authorization header", path);
            exchange.getResponse().setRawStatusCode(401);
            return exchange.getResponse().writeWith(Mono.just(
                exchange.getResponse().bufferFactory().wrap("Missing or invalid token".getBytes(StandardCharsets.UTF_8))
            ));
        }
 
        String token = authHeader.substring(7);
        try {
            PublicKey verificationKey = getVerificationKey(token);
            if (verificationKey == null) {
                log.warn("[SECURITY EVENT] Action=AUTHENTICATION_FAILURE Path={} Reason=Signing key not found for token verification", path);
                exchange.getResponse().setRawStatusCode(401);
                return exchange.getResponse().writeWith(Mono.just(
                    exchange.getResponse().bufferFactory().wrap("Signing key not found for token verification".getBytes(StandardCharsets.UTF_8))
                ));
            }
 
            Claims claims = Jwts.parser()
                    .verifyWith(verificationKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
 
            String username = claims.get("preferred_username", String.class);
            if (username == null) {
                username = claims.getSubject();
            }
 
            // Extract roles
            List<String> userRoles = new ArrayList<>();
            Map<String, Object> realmAccess = claims.get("realm_access", Map.class);
            if (realmAccess != null) {
                List<?> rolesList = (List<?>) realmAccess.get("roles");
                if (rolesList != null) {
                    for (Object r : rolesList) {
                        userRoles.add(r.toString().toUpperCase());
                    }
                }
            }
 
            // Extract tenant ID
            String tenant = claims.get("tenant", String.class);
            if (tenant == null) {
                String iss = claims.getIssuer();
                if (iss != null && iss.contains("/realms/")) {
                    tenant = iss.substring(iss.lastIndexOf("/realms/") + 8);
                }
            }
            if (username == null || !username.matches("^[a-zA-Z0-9_\\-@\\.]+$")) {
                username = "system";
            }
            if (tenant == null || !tenant.matches("^[a-zA-Z0-9_\\-]+$")) {
                tenant = "default";
            }
 
            // Perform RBAC
            String resource = getResourceName(path);
            if (resource != null) {
                ResourceMetadata<?, ?> metadata = crudManager.getMetadata(resource);
                if (metadata != null) {
                    Class<?> entityClass = metadata.getEntityClass();
                    CrudResource annotation = entityClass.getAnnotation(CrudResource.class);
                    if (annotation != null) {
                        String[] allowedRoles = annotation.roles();
                        boolean authorized = false;
                        for (String allowedRole : allowedRoles) {
                            if ("ANYONE".equalsIgnoreCase(allowedRole)) {
                                sortedCheck: {
                                    authorized = true;
                                    break;
                                }
                            }
                            if (userRoles.contains(allowedRole.toUpperCase())) {
                                authorized = true;
                                break;
                            }
                        }
 
                        if (!authorized) {
                            log.warn("[SECURITY EVENT] Action=ACCESS_DENIED Resource={} User={} Tenant={} Reason=Insufficient privileges", resource, username, tenant);
                            exchange.getResponse().setRawStatusCode(403);
                            return exchange.getResponse().writeWith(Mono.just(
                                exchange.getResponse().bufferFactory().wrap("Forbidden: Insufficient privileges".getBytes(StandardCharsets.UTF_8))
                            ));
                        }
                    }
                }
            }
 
            // Set tenant context & authentication in Reactive Context
            List<GrantedAuthority> authorities = new ArrayList<>();
            for (String role : userRoles) {
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            }
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
 
            final String finalTenant = tenant;
            final String finalUser = username;
            return chain.filter(exchange)
                    .contextWrite(Context.of("tenantId", finalTenant, "username", finalUser))
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
 
        } catch (io.jsonwebtoken.JwtException | IllegalArgumentException e) {
            log.warn("[SECURITY EVENT] Action=AUTHENTICATION_FAILURE Path={} Reason={}", path, e.getMessage());
            log.debug("Token verification failure details", e);
            exchange.getResponse().setRawStatusCode(401);
            return exchange.getResponse().writeWith(Mono.just(
                exchange.getResponse().bufferFactory().wrap(("Invalid token: " + e.getMessage()).getBytes(StandardCharsets.UTF_8))
            ));
        } catch (Exception e) {
            log.error("Unexpected error during token filtering", e);
            exchange.getResponse().setRawStatusCode(500);
            return exchange.getResponse().writeWith(Mono.just(
                exchange.getResponse().bufferFactory().wrap("Internal Server Error".getBytes(StandardCharsets.UTF_8))
            ));
        }
    }

    private String getResourceName(String path) {
        if (path.startsWith("/api/")) {
            String remaining = path.substring(5);
            // Ignore API versions if present (e.g. v1/products -> products)
            if (remaining.startsWith("v") && remaining.contains("/")) {
                int nextSlash = remaining.indexOf('/');
                if (Character.isDigit(remaining.charAt(nextSlash - 1)) || remaining.substring(0, nextSlash).matches("v\\d+")) {
                    remaining = remaining.substring(nextSlash + 1);
                }
            }
            int slashIdx = remaining.indexOf('/');
            if (slashIdx != -1) {
                return remaining.substring(0, slashIdx);
            } else {
                return remaining;
            }
        }
        return null;
    }

    private PublicKey getVerificationKey(String token) throws Exception {
        if (appModeConfig.isDevelopment() && testPublicKeyPem != null && !testPublicKeyPem.trim().isEmpty()) {
            synchronized (testKeyLock) {
                if (parsedTestPublicKey == null) {
                    parsedTestPublicKey = parsePemPublicKey(testPublicKeyPem);
                }
            }
            return parsedTestPublicKey;
        }

        String kid = extractKid(token);
        if (kid == null) {
            return null;
        }

        if (jwkCache.containsKey(kid)) {
            return jwkCache.get(kid);
        }

        fetchJwks();
        return jwkCache.get(kid);
    }

    private String extractKid(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length > 0) {
                String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
                Map<String, Object> header = objectMapper.readValue(headerJson, Map.class);
                return (String) header.get("kid");
            }
        } catch (Exception e) {
            log.warn("Failed to extract kid from token header", e);
        }
        return null;
    }

    private PublicKey parsePemPublicKey(String pem) throws Exception {
        String cleaned = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(cleaned);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    @SuppressWarnings("unchecked")
    private synchronized void fetchJwks() {
        try {
            log.info("Fetching Keycloak JWKS from: {}", jwkSetUri);
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(jwkSetUri))
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                log.error("Failed to fetch JWKS: status code {}", response.statusCode());
                return;
            }

            Map<String, Object> jwks = objectMapper.readValue(response.body(), Map.class);
            List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
            if (keys != null) {
                for (Map<String, Object> key : keys) {
                    String keyId = (String) key.get("kid");
                    String kty = (String) key.get("kty");
                    if ("RSA".equals(kty)) {
                        String n = (String) key.get("n");
                        String e = (String) key.get("e");

                        byte[] modulusBytes = Base64.getUrlDecoder().decode(n);
                        byte[] exponentBytes = Base64.getUrlDecoder().decode(e);
                        BigInteger modulus = new BigInteger(1, modulusBytes);
                        BigInteger exponent = new BigInteger(1, exponentBytes);
                        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
                        KeyFactory factory = KeyFactory.getInstance("RSA");
                        PublicKey publicKey = factory.generatePublic(spec);

                        jwkCache.put(keyId, publicKey);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error fetching or parsing JWKS from URL " + jwkSetUri, e);
        }
    }
}

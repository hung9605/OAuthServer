//package com.app.controller;
//
//import java.net.URI;
//import java.time.Instant;
//import java.util.Map;
//
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.oauth2.jwt.Jwt;
//import org.springframework.security.oauth2.jwt.JwtDecoder;
//import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
//import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
//import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
//import org.springframework.session.FindByIndexNameSessionRepository;
//import org.springframework.session.Session;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RequestParam;
//import org.springframework.web.bind.annotation.RestController;
//
//import com.app.service.RedisTokenBlacklistService;
//
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpSession;
//
//@RestController("/oauth2")
//public class LogoutController {
//
//    private final OAuth2AuthorizationService authorizationService;
//    private final JwtDecoder jwtDecoder;
//    
//    private final FindByIndexNameSessionRepository<? extends Session> sessionRepository;
//    private final RedisTokenBlacklistService blacklistService;
//
//    public LogoutController(
//            OAuth2AuthorizationService authorizationService,
//            JwtDecoder jwtDecoder,
//            FindByIndexNameSessionRepository<? extends Session> sessionRepository,
//            RedisTokenBlacklistService blacklistService) {
//        this.authorizationService = authorizationService;
//        this.jwtDecoder = jwtDecoder;
//        this.sessionRepository = sessionRepository;
//        this.blacklistService = blacklistService;
//    }
//
//
//    @GetMapping("/logout-rp")
//    public ResponseEntity<Void> rpInitiatedLogout(
//            @RequestParam("id_token_hint") String idTokenHint,
//            @RequestParam(value = "post_logout_redirect_uri", required = false) String postLogoutRedirectUri,
//            HttpServletRequest request) {
//
//        // 1) Decode id_token_hint lấy principal (sub)
//        Jwt idToken;
//        try {
//            idToken = jwtDecoder.decode(idTokenHint);
//        } catch (Exception e) {
//            // Token invalid, trả lỗi 400 Bad Request
//            return ResponseEntity.badRequest().build();
//        }
//        String principalName = idToken.getSubject();
//        if (principalName == null || principalName.isEmpty()) {
//            return ResponseEntity.badRequest().build();
//        }
//
//        // 2) Lấy access_token từ header hoặc param để revoke authorization
//        String accessTokenValue = extractAccessToken(request);
//
//        if (accessTokenValue != null) {
//            OAuth2Authorization auth = authorizationService.findByToken(accessTokenValue, OAuth2TokenType.ACCESS_TOKEN);
//            if (auth != null) {
//                revokeAuthorization(auth);
//                authorizationService.remove(auth);
//            }
//        }
//
//      //   3) Xóa tất cả session liên quan principal (nếu sessionRepository có)
//        if (sessionRepository != null) {
//            Map<String, ? extends Session> sessions = sessionRepository.findByIndexNameAndIndexValue(
//                    FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, principalName);
//            if (sessions != null) {
//                sessions.keySet().forEach(sessionRepository::deleteById);
//            }
//        }
//
//        // 4) Invalidate session hiện tại nếu có
//        HttpSession session = request.getSession(false);
//        if (session != null) {
//            session.invalidate();
//        }
//
//        // 5) Redirect nếu có post_logout_redirect_uri
//        if (postLogoutRedirectUri != null && !postLogoutRedirectUri.isEmpty()) {
//            HttpHeaders headers = new HttpHeaders();
//            headers.setLocation(URI.create(postLogoutRedirectUri));
//            return new ResponseEntity<>(headers, HttpStatus.FOUND);
//        }
//
//        return ResponseEntity.ok().build();
//    }
//
//    private void revokeAuthorization(OAuth2Authorization authorization) {
//        if (authorization.getAccessToken() != null && authorization.getAccessToken().getToken() != null) {
//            var accessToken = authorization.getAccessToken().getToken();
//            blacklistIfNeeded(accessToken.getTokenValue(), accessToken.getExpiresAt());
//        }
//
//        if (authorization.getRefreshToken() != null && authorization.getRefreshToken().getToken() != null) {
//            var refreshToken = authorization.getRefreshToken().getToken();
//            blacklistIfNeeded(refreshToken.getTokenValue(), refreshToken.getExpiresAt());
//        }
//
//        var idToken = authorization.getToken(org.springframework.security.oauth2.core.oidc.OidcIdToken.class);
//        if (idToken != null && idToken.getToken() != null) {
//            blacklistIfNeeded(idToken.getToken().getTokenValue(), idToken.getToken().getExpiresAt());
//        }
//    }
//
//    private void blacklistIfNeeded(String tokenValue, Instant expiresAt) {
//        long ttl = expiresAt != null ? Math.max(0, expiresAt.getEpochSecond() - Instant.now().getEpochSecond()) : 0;
//        if (ttl > 0 && blacklistService != null) {
//            blacklistService.blacklist(tokenValue, ttl);
//        }
//    }
//
//    private String extractAccessToken(HttpServletRequest request) {
//        // Tìm access token trong header Authorization Bearer
//        String authHeader = request.getHeader("Authorization");
//        if (authHeader != null && authHeader.startsWith("Bearer ")) {
//            return authHeader.substring(7);
//        }
//        // Hoặc từ query param access_token
//        String tokenParam = request.getParameter("access_token");
//        if (tokenParam != null && !tokenParam.isEmpty()) {
//            return tokenParam;
//        }
//        return null;
//    }
//}

package com.springsecurity.social.controller;

import java.net.URI;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.springsecurity.social.entities.AuthProvider;
import com.springsecurity.social.entities.User;
import com.springsecurity.social.exception.BadRequestException;
import com.springsecurity.social.payload.ApiResponse;
import com.springsecurity.social.payload.LoginRequest;
import com.springsecurity.social.payload.SignUpRequest;
import com.springsecurity.social.repository.UserRepository;
import com.springsecurity.social.security.TokenProvider;
import com.springsecurity.social.util.CookieUtils;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenProvider tokenProvider;

    private static final String ACCESS_TOKEN_COOKIE_NAME = "access_token";
    private static final String REFRESH_TOKEN_COOKIE_NAME = "refresh_token";
    private static final int ACCESS_TOKEN_VALIDITY = 7 * 24 * 60 * 60; // 7 days
    private static final int REFRESH_TOKEN_VALIDITY = 30 * 24 * 60 * 60; // 30 days

    public AuthController(
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            TokenProvider tokenProvider) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenProvider = tokenProvider;
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest,
            HttpServletResponse response) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),
                        loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Generate tokens
        String accessToken = tokenProvider.createAccessToken(authentication);
        String refreshToken = tokenProvider.createRefreshToken(authentication);

        // Add tokens as HTTP-only cookies
        addTokenCookies(response, accessToken, refreshToken);

        return ResponseEntity.ok(new ApiResponse(true, "Login successful"));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new BadRequestException("Email address already in use.");
        }

        // Creating user's account
        User user = new User();
        user.setName(signUpRequest.getName());
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
        user.setProvider(AuthProvider.local);

        User result = userRepository.save(user);

        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath().path("/user/me")
                .buildAndExpand(result.getId()).toUri();

        return ResponseEntity.created(location)
                .body(new ApiResponse(true, "User registered successfully"));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@CookieValue(REFRESH_TOKEN_COOKIE_NAME) String refreshToken,
            HttpServletResponse response) {
        if (!tokenProvider.validateToken(refreshToken)) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "Invalid refresh token"));
        }

        Long userId = tokenProvider.getUserIdFromToken(refreshToken);
        String newAccessToken = tokenProvider.createAccessToken(userId);

        // Add new access token as HTTP-only cookie
        CookieUtils.addCookie(response, ACCESS_TOKEN_COOKIE_NAME, newAccessToken, ACCESS_TOKEN_VALIDITY);

        return ResponseEntity.ok(new ApiResponse(true, "Token refreshed successfully"));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        // Clear the authentication tokens
        CookieUtils.deleteCookie(null, response, ACCESS_TOKEN_COOKIE_NAME);
        CookieUtils.deleteCookie(null, response, REFRESH_TOKEN_COOKIE_NAME);

        SecurityContextHolder.clearContext();

        return ResponseEntity.ok(new ApiResponse(true, "Logged out successfully"));
    }

    private void addTokenCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        CookieUtils.addCookie(response, ACCESS_TOKEN_COOKIE_NAME, accessToken, ACCESS_TOKEN_VALIDITY);
        CookieUtils.addCookie(response, REFRESH_TOKEN_COOKIE_NAME, refreshToken, REFRESH_TOKEN_VALIDITY);
    }
}

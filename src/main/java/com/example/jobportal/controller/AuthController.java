package com.example.jobportal.controller;

import com.example.jobportal.entity.User;
import com.example.jobportal.service.JwtService;
import com.example.jobportal.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private UserService userService;
    @Autowired
    private JwtService jwtService;

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody User user) {
        return ResponseEntity.ok(userService.signup(user));
    }

    @PostMapping("/verify")
    public ResponseEntity<String> verify(@RequestParam String email, @RequestParam String otp) {
        String result = userService.verifyEmail(email, otp);
        if ("Verified".equals(result)) {
            return ResponseEntity.ok(result);
        } else {
            return ResponseEntity.badRequest().body(result);
        }
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<String> resendOtp(@RequestParam String email) {
        String result = userService.resendOtp(email);
        if (result.startsWith("New OTP")) {
            return ResponseEntity.ok(result);
        } else {
            return ResponseEntity.badRequest().body(result);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody User loginUser, HttpServletResponse response) {
        User user = userService.login(loginUser.getEmail(), loginUser.getPassword());
        if (user != null) {
            String accessToken = jwtService.generateAccessToken(user.getId());
            String refreshToken = jwtService.generateRefreshToken(user.getId());

            // Store tokens in HTTP-only cookies
            Cookie accessCookie = new Cookie("accessToken", accessToken);
            accessCookie.setHttpOnly(true);
            accessCookie.setPath("/");
            response.addCookie(accessCookie);

            Cookie refreshCookie = new Cookie("refreshToken", refreshToken);
            refreshCookie.setHttpOnly(true);
            refreshCookie.setPath("/");
            response.addCookie(refreshCookie);

            // Frontend will store id/name in localStorage separately
            return ResponseEntity.ok("Login successful. User ID: " + user.getId() + ", Name: " + user.getName());
        }
        return ResponseEntity.badRequest().body("Invalid credentials");
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletResponse response) {
        // Clear cookies
        Cookie accessCookie = new Cookie("accessToken", "");
        accessCookie.setMaxAge(0);
        response.addCookie(accessCookie);

        Cookie refreshCookie = new Cookie("refreshToken", "");
        refreshCookie.setMaxAge(0);
        response.addCookie(refreshCookie);

        return ResponseEntity.ok("Logged out");
    }

    @PostMapping("/refresh")
    public ResponseEntity<String> refresh(@CookieValue("refreshToken") String refreshToken, HttpServletResponse response) {
        if (jwtService.isTokenValid(refreshToken)) {
            Long userId = jwtService.extractUserId(refreshToken);
            String newAccessToken = jwtService.generateAccessToken(userId);
            Cookie accessCookie = new Cookie("accessToken", newAccessToken);
            accessCookie.setHttpOnly(true);
            accessCookie.setPath("/");
            response.addCookie(accessCookie);
            return ResponseEntity.ok("Token refreshed");
        }
        return ResponseEntity.badRequest().body("Invalid refresh token");
    }

    @GetMapping("/debug/users")
    public ResponseEntity<String> debugUsers() {
        return ResponseEntity.ok(userService.debugUsers());
    }
}
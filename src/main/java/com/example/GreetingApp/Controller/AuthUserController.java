package com.example.GreetingApp.Controller;

import com.example.GreetingApp.Model.AuthUser;
import com.example.GreetingApp.Service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Collections;

@RestController
@RequestMapping("/auth")
public class AuthUserController {

    @Autowired
    private AuthenticationService authenticationService;

    // Register User
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody AuthUser authUser) {
        String response = authenticationService.registerUser(authUser);
        return ResponseEntity.ok(response);
    }

    // Login User and Generate JWT Token
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String password = request.get("password");

        if (email == null || password == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email and password are required!"));
        }

        String token = authenticationService.authenticateUser(email, password);

        if ("User not found!".equals(token)) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found!"));
        } else if ("Invalid email or password!".equals(token)) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid email or password!"));
        }

        return ResponseEntity.ok(Map.of("message", "Login successful!", "token", token));
    }

    // Forgot Password - Reset password if user forgets it
    @PutMapping("/forgotPassword/{email}")
    public ResponseEntity<?> forgotPassword(@PathVariable String email, @RequestBody Map<String, String> request) {
        String newPassword = request.get("password");

        if (newPassword == null || newPassword.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "New password is required!"));
        }

        String response = authenticationService.forgotPassword(email, newPassword);
        return ResponseEntity.ok(Collections.singletonMap("message", response));
    }

    // Reset Password - Logged-in user can change password
    @PutMapping("/resetPassword")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String currentPassword = request.get("currentPassword");
        String newPassword = request.get("newPassword");

        if (email == null || currentPassword == null || newPassword == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email, current password, and new password are required!"));
        }

        String response = authenticationService.resetPassword(email, currentPassword, newPassword);
        return ResponseEntity.ok(Collections.singletonMap("message", response));
    }
}

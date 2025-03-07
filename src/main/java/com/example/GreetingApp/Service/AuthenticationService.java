package com.example.GreetingApp.Service;

import com.example.GreetingApp.Model.AuthUser;
import com.example.GreetingApp.Repository.AuthUserRepository;
import com.example.GreetingApp.Security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.logging.Logger;

@Service
public class AuthenticationService {

    @Autowired
    private AuthUserRepository authUserRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private EmailService emailService;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private static final Logger LOGGER = Logger.getLogger(AuthenticationService.class.getName());

    // Register User
    public String registerUser(AuthUser authUser) {
        if (authUserRepository.existsByEmail(authUser.getEmail())) {
            return "Email is already in use!";
        }

        // Ensure password is hashed before saving
        authUser.setPassword(passwordEncoder.encode(authUser.getPassword()));
        authUserRepository.save(authUser);

        String subject = "Successful Registration Notification";
        String content = "<h2>Hello " + authUser.getFirstName() + ",</h2>"
                + "<p>Your account has been successfully created!</p>"
                + "<p>Welcome to GreetingApp 🎉</p>"
                + "<br><p>Regards,</p><p><strong>GreetingsApp Team</strong></p>";

        emailService.sendEmail(authUser.getEmail(), subject, content);

        return "User registered successfully!";
    }

    // Authenticate User and Generate Token
    public String authenticateUser(String email, String password) {
        Optional<AuthUser> userOpt = authUserRepository.findByEmail(email);

        if (userOpt.isEmpty()) {
            return "User not found!";
        }

        AuthUser user = userOpt.get();

        // Logging instead of System.out.println() for better debugging
        LOGGER.info("Stored Hashed Password: " + user.getPassword());
        LOGGER.info("Raw Password: " + password);
        LOGGER.info("Match Result: " + passwordEncoder.matches(password, user.getPassword()));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            return "Invalid email or password!";
        }

        // Generate JWT Token
        return jwtUtil.generateToken(email);
    }

    // Forgot Password - Reset password if user forgets it
    public String forgotPassword(String email, String newPassword) {
        Optional<AuthUser> userOpt = authUserRepository.findByEmail(email);

        if (userOpt.isEmpty()) {
            return "Sorry! We cannot find the user email: " + email;
        }

        AuthUser user = userOpt.get();

        // Hash the new password before saving
        user.setPassword(passwordEncoder.encode(newPassword));
        authUserRepository.save(user);

        // Send email notification
        String subject = "Password Reset Confirmation";
        String content = "<h2>Hello " + user.getFirstName() + ",</h2>"
                + "<p>Your password has been successfully changed.</p>"
                + "<p>If you did not request this, please contact support immediately.</p>"
                + "<br><p>Regards,</p><p><strong>GreetingsApp Team</strong></p>";

        emailService.sendEmail(user.getEmail(), subject, content);

        return "Password has been changed successfully!";
    }

    // Reset Password - Logged-in user can change password
    public String resetPassword(String email, String currentPassword, String newPassword) {
        Optional<AuthUser> userOpt = authUserRepository.findByEmail(email);

        if (userOpt.isEmpty()) {
            return "User not found with email: " + email;
        }

        AuthUser user = userOpt.get();

        // Validate current password
        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            return "Current password is incorrect!";
        }

        // Hash the new password before saving
        user.setPassword(passwordEncoder.encode(newPassword));
        authUserRepository.save(user);

        // Send email notification for password change
        String subject = "Password Reset Confirmation";
        String content = "<h2>Hello " + user.getFirstName() + ",</h2>"
                + "<p>Your password has been successfully updated.</p>"
                + "<p>If you did not request this change, please contact support immediately.</p>"
                + "<br><p>Regards,</p><p><strong>GreetingsApp Team</strong></p>";

        emailService.sendEmail(user.getEmail(), subject, content);

        return "Password reset successfully!";
    }
}

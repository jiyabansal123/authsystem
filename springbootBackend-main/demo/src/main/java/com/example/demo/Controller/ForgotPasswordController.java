package com.example.demo.Controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.Model.MyAppUser;
import com.example.demo.Model.MyAppUserRepository;
import com.example.demo.service.EmailService;
import com.example.demo.utils.JwtTokenUtil;

@RestController
public class ForgotPasswordController {

    private final MyAppUserRepository userRepository;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;
    private final com.example.demo.utils.JwtTokenUtil jwtTokenUtil;

    public ForgotPasswordController(MyAppUserRepository userRepository, EmailService emailService,
                                    PasswordEncoder passwordEncoder, com.example.demo.utils.JwtTokenUtil jwtTokenUtil) {
        this.userRepository = userRepository;
        this.emailService = emailService;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @PostMapping(value = "/req/forgot-password", consumes = "application/json")
    public ResponseEntity<String> requestReset(@RequestBody java.util.Map<String, String> body) {
        String email = body != null ? body.get("email") : null;
        if (email == null || email.isBlank()) {
            return ResponseEntity.badRequest().body("Email is required.");
        }
        MyAppUser user = userRepository.findByEmail(email.trim());
        if (user == null) {
            return ResponseEntity.ok("If an account exists for this email, you will receive a reset link.");
        }
        String resetToken = JwtTokenUtil.generateResetToken(user.getEmail());
        user.setResetToken(resetToken);
        userRepository.save(user);
        emailService.sendForgotPasswordEmail(user.getEmail(), resetToken);
        return ResponseEntity.ok("If an account exists for this email, you will receive a reset link.");
    }

    @PostMapping(value = "/req/reset-password", consumes = "application/json")
    public ResponseEntity<String> resetPassword(@RequestBody java.util.Map<String, String> body) {
        String token = body != null ? body.get("token") : null;
        String newPassword = body != null ? body.get("newPassword") : null;
        if (token == null || token.isBlank() || newPassword == null || newPassword.isBlank()) {
            return ResponseEntity.badRequest().body("Token and new password are required.");
        }
        if (!jwtTokenUtil.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid or expired reset link.");
        }
        try {
            String email = jwtTokenUtil.extractEmail(token);
            MyAppUser user = userRepository.findByEmail(email);
            if (user == null || !token.equals(user.getResetToken())) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid or expired reset link.");
            }
            user.setPassword(passwordEncoder.encode(newPassword));
            user.setResetToken(null);
            userRepository.save(user);
            return ResponseEntity.ok("Password has been reset. You can now log in.");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid or expired reset link.");
        }
    }
}

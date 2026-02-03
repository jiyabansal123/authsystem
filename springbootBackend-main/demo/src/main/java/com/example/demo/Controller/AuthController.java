package com.example.demo.Controller;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.Model.MyAppUser;
import com.example.demo.Model.MyAppUserRepository;
import com.example.demo.utils.JwtTokenUtil;

@RestController
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final MyAppUserRepository userRepository;

    public AuthController(AuthenticationManager authenticationManager, MyAppUserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
    }

    @PostMapping(value = "/req/auth/login", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");
        if (username == null || password == null) {
            return ResponseEntity.badRequest().body(Map.of("message", "Username and password required"));
        }

        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));
            MyAppUser user = userRepository.findByUsername(username).orElse(null);
            if (user == null || !user.isVerified()) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("message", "Account not verified"));
            }
            String role = user.getRole() != null ? user.getRole() : MyAppUser.ROLE_USER;
            String token = JwtTokenUtil.generateTokenWithRole(user.getEmail(), role);
            return ResponseEntity.ok(Map.of("token", token, "role", role, "username", user.getUsername()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Invalid credentials"));
        }
    }
}

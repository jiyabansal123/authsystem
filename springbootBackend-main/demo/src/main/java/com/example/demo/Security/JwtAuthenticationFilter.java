package com.example.demo.Security;

import java.io.IOException;
import java.util.Collections;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.demo.Model.MyAppUser;
import com.example.demo.Model.MyAppUserRepository;
import com.example.demo.utils.JwtTokenUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenUtil jwtTokenUtil;
    private final MyAppUserRepository userRepository;

    public JwtAuthenticationFilter(JwtTokenUtil jwtTokenUtil, MyAppUserRepository userRepository) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);

        if (!jwtTokenUtil.validateToken(token) || !jwtTokenUtil.isAccessToken(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String email = jwtTokenUtil.extractEmail(token);
            String role = jwtTokenUtil.extractRole(token);
            MyAppUser appUser = userRepository.findByEmail(email);

            if (appUser == null || !appUser.isVerified()) {
                filterChain.doFilter(request, response);
                return;
            }

            String authority = role.startsWith("ROLE_") ? role : "ROLE_" + role;
            UserDetails userDetails = User.builder()
                    .username(appUser.getUsername())
                    .password(appUser.getPassword())
                    .authorities(Collections.singletonList(new SimpleGrantedAuthority(authority)))
                    .build();

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            // Invalid or expired token – continue without authentication
        }

        filterChain.doFilter(request, response);
    }
}

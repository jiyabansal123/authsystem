package com.example.demo.Controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ContentController {

    @GetMapping("/dashboard")
    public String dashboard(Authentication auth, Model model) {
        if (auth != null && auth.isAuthenticated()) {
            model.addAttribute("username", auth.getName());
            String role = auth.getAuthorities().isEmpty() ? "USER" : auth.getAuthorities().iterator().next().getAuthority();
            model.addAttribute("role", role.startsWith("ROLE_") ? role.substring(5) : role);
        }
        return "dashboard";
    }

    @GetMapping("/req/login")
    public String login(){
        return "login";
    }
    
    @GetMapping("/req/signup")
    public String signup(){
        return "signup";
    }
    @GetMapping("/index")
    public String home(){
        return "index";
    }

    @GetMapping("/req/forgot-password")
    public String forgotPasswordPage(){
        return "forgot-password";
    }

    @GetMapping("/req/reset-password")
    public String resetPasswordPage(){
        return "reset-password";
    }
}

package com.springsecurity.spring.security.project.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/home")
    public String home(Model model, @AuthenticationPrincipal OidcUser principal) {
        if (principal != null) {
            // Try to get the user's full name
            String fullName = principal.getFullName();
            if (fullName == null) {
                fullName = principal.getGivenName();
                if (fullName == null) {
                    fullName = principal.getName();
                }
            }

            String email = principal.getEmail();
            model.addAttribute("name", fullName);
            model.addAttribute("email", email);



//            logger.info("Principal full name: {}", fullName);
//            logger.info("Principal email: {}", email);
        } else {
//            logger.warn("Principal is null");
        }

        return "home"; // Return the home.html page
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}

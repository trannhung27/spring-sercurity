package com.example.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {
    @GetMapping("/login")
    public String loginEndpoint() {
//        Authentication authentication = authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(
//                        loginRequest.getUsername(),
//                        loginRequest.getPassword()
//                )
//        );
//
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        // Trả về jwt cho người dùng.
//        String jwt = tokenProvider.generateToken((CustomUserDetails) authentication.getPrincipal());
//        return new LoginResponse(jwt);
        return "Login!";
    }

    @GetMapping("/admin")
    public String adminEndpoint() {
        return "Admin!";
    }

    @GetMapping("/user")
    public String userEndpoint() {
        return "User!";
    }

    @GetMapping("/all")
    public String allRolesEndpoint() {
        return "All Roles!";
    }

    @DeleteMapping("/delete")
    public String deleteEndpoint(@RequestBody String s) {
        return "I am deleting " + s;
    }
}

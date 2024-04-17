package com.example.security;

import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class UserService {

    public UserDetails loadUserById(Long userId){
        UserDetails  userDetails = new UserDetails(1L,"nhung", Collections.singleton("USER"));
        return userDetails;
    }
}

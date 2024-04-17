package com.example.security;


import lombok.Getter;
import lombok.Setter;

import java.util.Collection;

@Getter
@Setter
public class UserDetails {
    private Long id;
    private String userName;
    private Collection authorities;

    public UserDetails(Long id, String userName, Collection authorities) {
        this.id = id;
        this.userName = userName;
        this.authorities = authorities;
    }
}

package com.example.security;


import lombok.Getter;
import lombok.Setter;

import java.util.Collection;

@Getter
@Setter
public class UserDetails {
    private Long id;
    private String userName;
    private String password;
    private Collection authority;

    public UserDetails(Long id, String userName, String password, Collection authorities) {
        this.id = id;
        this.userName = userName;
        this.password = password;
        this.authority = authorities;
    }
}

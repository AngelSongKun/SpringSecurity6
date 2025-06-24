package com.jankin.springsecurity6.dto;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class MyUserDetails implements UserDetails {
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        List<String> roles = new ArrayList<String>();
        roles.add("admin");
        roles.add("user");

        List<SimpleGrantedAuthority> authorities = roles.stream()
                .map(SimpleGrantedAuthority::new) // 将字符串包装为 SimpleGrantedAuthority
                .toList();

        return authorities;
    }

    @Override
    public String getPassword() {
        String password = "123456";
        return password;
    }

    @Override
    public String getUsername() {
        String username = "admin";
        return username;
    }
}

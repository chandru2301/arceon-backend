package com.git.security;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // In a real application, you would fetch user details from a database
        // For this implementation, we'll create a simple user with ROLE_USER
        // You should replace this with actual user lookup logic
        
        return new User(username, "", 
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
    }
}
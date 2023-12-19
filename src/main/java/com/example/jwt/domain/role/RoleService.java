package com.example.jwt.domain.role;

import com.example.jwt.core.generic.ExtendedService;
import com.example.jwt.domain.user.User;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.Optional;

public interface RoleService extends ExtendedService<Role> {
    Role findByName(String name);
}
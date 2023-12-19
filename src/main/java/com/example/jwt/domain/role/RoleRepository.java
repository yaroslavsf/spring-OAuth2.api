package com.example.jwt.domain.role;

import com.example.jwt.core.generic.ExtendedRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface RoleRepository extends ExtendedRepository<Role> {
    Role findByName(String name);
}
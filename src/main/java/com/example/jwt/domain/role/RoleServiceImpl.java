package com.example.jwt.domain.role;

import com.example.jwt.core.generic.ExtendedServiceImpl;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class RoleServiceImpl extends ExtendedServiceImpl<Role> implements RoleService {

    @Autowired
    public RoleServiceImpl(RoleRepository repository, Logger logger) {
        super(repository, logger);
    }
    @Override
    public Role findByName(String name) {
        return ((RoleRepository)this.repository).findByName(name);
    }
}
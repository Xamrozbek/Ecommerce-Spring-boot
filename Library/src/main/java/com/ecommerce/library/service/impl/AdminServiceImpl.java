package com.ecommerce.library.service.impl;

import com.ecommerce.library.dto.AdminDto;
import com.ecommerce.library.model.Admin;
import com.ecommerce.library.repository.AdminRepository;
import com.ecommerce.library.repository.RoleRepository;
import com.ecommerce.library.service.AdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service

public class AdminServiceImpl implements AdminService {

    private BCryptPasswordEncoder passwordEncoder;
    @Autowired
    private AdminRepository adminRepository;
    @Autowired
    private RoleRepository roleRepository;


    @Override
    public Admin findByUsername(String username) {
        return adminRepository.findAdminByUsername(username);
    }

    @Override
    public Admin save(AdminDto adminDto) {
        Admin admin = Admin.builder()
                .firstName(adminDto.getFirstName())
                .lastName(adminDto.getLastName())
                .username(adminDto.getUsername())
                .password(passwordEncoder.encode(adminDto.getPassword()))
                .roles(Collections.singletonList(roleRepository.findByName("ADMIN")))
                .build();

        return adminRepository.save(admin);
    }
}

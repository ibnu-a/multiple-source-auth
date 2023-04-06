package com.example.api.service;

import com.example.api.dto.AdminDto;
import com.example.api.model.Admin;
import com.example.api.model.ERole;
import com.example.api.repository.AdminRepository;
import com.example.api.security.JwtProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class AdminService {

    private final AdminRepository adminRepository;
    private final JwtProvider jwtProvider;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;


    public Admin registerAdmin(AdminDto.RequestRegisterAdmin req) {
        log.info("data password: {}", req.getPassword());
        Admin admin = new Admin();
        admin.setUsername(req.getUsername());
        admin.setEmail(req.getEmail());
        admin.setName(req.getName());
        admin.setPassword(passwordEncoder.encode(req.getPassword()));

        ERole role = Optional.ofNullable(req.getRole())
                .map(roleName ->
                        roleName.equalsIgnoreCase("admin") ? ERole.ROLE_ADMIN : ERole.ROLE_MODERATOR)
                .orElse(ERole.ROLE_MODERATOR);

        admin.setRole(role);
        adminRepository.save(admin);
        log.info("User {} registered successfully!", admin.getUsername());
        return admin;
    }

    public AdminDto.ResponseLoginAdmin loginAdmin(AdminDto.RequestLoginAdmin req) {

        log.info("1");
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        req.getUsername(),
                        req.getPassword()
                )
        );

        log.info("2");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        Admin admin = adminRepository.findByUsername(req.getUsername());
        String token = jwtProvider.generateToken(admin);
        String refreshToken = jwtProvider.generateRefreshToken(admin);


        AdminDto.ResponseLoginAdmin res = new AdminDto.ResponseLoginAdmin();
        res.setToken(token);
        res.setRefreshToken(refreshToken);
        res.setId(admin.getId());
        res.setUsername(admin.getUsername());
        res.setName(admin.getName());
        res.setRole(admin.getRole().name());

        log.info("Success login");
        return res;
    }
}

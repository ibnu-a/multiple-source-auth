package com.example.api.controller;

import com.example.api.dto.AdminDto;
import com.example.api.model.Admin;
import com.example.api.service.AdminService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
@Slf4j
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;


    @PostMapping("/register")
    public ResponseEntity<?> registerAdmin(@RequestBody AdminDto.RequestRegisterAdmin req) {

        Admin registerAdmin = adminService.registerAdmin(req);
        return ResponseEntity.ok(registerAdmin);
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginAdmin(@RequestBody AdminDto.RequestLoginAdmin req) {
        try {
            log.info("controller 1");
            AdminDto.ResponseLoginAdmin loginAdmin = adminService.loginAdmin(req);
            return ResponseEntity.ok(loginAdmin);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

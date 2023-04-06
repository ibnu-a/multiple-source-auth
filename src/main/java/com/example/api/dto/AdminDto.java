package com.example.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

public class AdminDto {

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RequestRegisterAdmin {
        private String username;
        private String email;
        private String name;
        private String role;
        private String password;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RequestLoginAdmin {
        private String username;
        private String password;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ResponseLoginAdmin {
        private String token;
        private String refreshToken;
        private UUID id;
        private String username;
        private String name;
        private String role;
    }


}

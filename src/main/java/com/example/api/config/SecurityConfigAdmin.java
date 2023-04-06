package com.example.api.config;

import com.example.api.repository.AdminRepository;
import com.example.api.security.AuthEntryPoint;
import com.example.api.security.AuthTokenFilterAdmin;
import com.example.api.service.AdminDetailsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration("customSecurityConfigWeb")
@Order(1)
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfigAdmin {

    private final AuthEntryPoint unauthorizedHandler;
    private final AuthTokenFilterAdmin authTokenFilterAdmin;
//    private final AdminRepository adminRepository;

    private static final String[] AUTH_WHITELIST_ADMIN = {
            "/api/admin/register",
            "/api/admin/login"
    };

//    public UserDetailsService admDetailsService() {
//        return new AdminDetailsService(adminRepository);
//    }

    @Bean
    public PasswordEncoder passwordEncoderAdmin() {
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    public AuthenticationProvider authenticationProviderAdmin() {
//        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
//        authProvider.setUserDetailsService(admDetailsService());
//        authProvider.setPasswordEncoder(passwordEncoderAdmin());
//
//        return authProvider;
//    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfiguration) throws Exception {
        return authConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChainAdmin(HttpSecurity http) throws Exception {
        return http
                .antMatcher("/api/admin/**")
                .csrf(csrf ->
                        csrf.disable())
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(unauthorizedHandler))
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeRequests(auth -> {
                    auth.antMatchers(AUTH_WHITELIST_ADMIN).permitAll();
                    auth.anyRequest().authenticated();
                })

                .addFilterBefore(authTokenFilterAdmin, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}

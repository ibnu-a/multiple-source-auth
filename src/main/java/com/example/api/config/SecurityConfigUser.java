package com.example.api.config;

import com.example.api.repository.UserRepository;
import com.example.api.security.AuthEntryPoint;
import com.example.api.security.AuthTokenFilterAdmin;
import com.example.api.service.UsersDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration("customSecurityConfigUser")
@Order(2)
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfigUser {

    private final AuthEntryPoint unauthorizedHandler;
    private final AuthTokenFilterAdmin authenticationJwtTokenFilter;
    private final UserRepository userRepository;

    @Lazy
    private PasswordEncoder passwordEncoder;

    public UserDetailsService userDetailsService(){
        return new UsersDetailsService(userRepository);
    }

//     @Bean
    public AuthenticationProvider authenticationProviderUser() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder);

        return authProvider;
    }

    @Bean
    public SecurityFilterChain filterChainUser(HttpSecurity http) throws Exception {
        return http
                .antMatcher("/api/user/**")
                .csrf(csrf ->
                        csrf.disable())
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(unauthorizedHandler))
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeRequests(auth -> {
                    auth.antMatchers("/api/user/register", "/api/user/login").permitAll();
                    auth.anyRequest().authenticated();
                })

                .addFilterBefore(authenticationJwtTokenFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}

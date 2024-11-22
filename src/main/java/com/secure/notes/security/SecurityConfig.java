package com.secure.notes.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//    @Bean
//    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests((requests) -> {
//            ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl)requests
//                    .requestMatchers("/contact").permitAll()
//                    .requestMatchers("/public/**").permitAll()
//                    .requestMatchers("/admin").denyAll()
//                    .requestMatchers("/admin/**").denyAll()
//                    .anyRequest()).authenticated();
//        });
////        http.formLogin(Customizer.withDefaults());
//
//        http.csrf(csrf -> csrf.disable());
//        http.sessionManagement(session ->
//                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        http.httpBasic(Customizer.withDefaults());
//        return http.build();
//    }
//}

public class SecurityConfig {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
        http.csrf(AbstractHttpConfigurer::disable);
        //http.formLogin(withDefaults());
        http.httpBasic(Customizer.withDefaults());
        return http.build();
    }
}


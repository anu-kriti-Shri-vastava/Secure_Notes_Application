package com.secure.notes.security;


//********************* TO BLOCK OR ALLOW REQUESTS ON CERTAIN URL *********************************

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


//*********************************** FOR INMEMORY AUTHENTICATION FOR TESTING PURPOSE ***********************************

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//    @Bean
//    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests((requests)
//                -> requests.anyRequest().authenticated());
//        http.csrf(AbstractHttpConfigurer::disable);
//        //http.formLogin(withDefaults());
//        http.httpBasic(withDefaults());
//        return http.build();
//    }
//
//    @Bean
//    public UserDetailsService userDetailsService() {
//        InMemoryUserDetailsManager manager =
//                new InMemoryUserDetailsManager();
//        if (!manager.userExists("user1")) {
//            manager.createUser(
//                    User.withUsername("user1")
//                            .password("{noop}password1")
//                            .roles("USER")
//                            .build()
//            );
//        }
//        if (!manager.userExists("admin")) {
//            manager.createUser(
//                    User.withUsername("admin")
//                            .password("{noop}adminPass")
//                            .roles("ADMIN")
//                            .build()
//            );
//        }
//        return manager;
//    }
//
//}


//*************************** USING JDBC MANAGER TO ACTUALLY CREATE USERS IN DATABASE *******************************
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests)
                -> requests.anyRequest().authenticated());
        http.csrf(AbstractHttpConfigurer::disable);
        //http.formLogin(withDefaults());
        http.httpBasic(withDefaults());
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource datasource) {
        JdbcUserDetailsManager manager =
                new JdbcUserDetailsManager(datasource);
        if (!manager.userExists("user1")) {
            manager.createUser(
                    User.withUsername("user1")
                            .password("{noop}password1")
                            .roles("USER")
                            .build()
            );
        }
        if (!manager.userExists("admin")) {
            manager.createUser(
                    User.withUsername("admin")
                            .password("{noop}adminPass")
                            .roles("ADMIN")
                            .build()
            );
        }
        return manager;
    }

}





package dev.ashutosh.sc.learnSpringSecurity.config;

import dev.ashutosh.sc.learnSpringSecurity.jwtutils.JwtAuthenticationEntryPoint;
import dev.ashutosh.sc.learnSpringSecurity.jwtutils.JwtFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration 
@EnableWebSecurity
public class WebSecurityConfig {

   @Autowired
   private JwtAuthenticationEntryPoint authenticationEntryPoint;
   @Autowired
   private JwtFilter filter;

   @Bean 
   protected PasswordEncoder passwordEncoder() { 
      return new BCryptPasswordEncoder(); 
   }

   @Bean
   protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception { 
      return http
         .csrf(AbstractHttpConfigurer::disable) //This disables Cross-Site Request Forgery (CSRF) protection, which is commonly disabled in stateless applications like those using JWT tokens.
         .authorizeHttpRequests(request -> request.requestMatchers("/login").permitAll() //It allows unauthenticated access to the /login endpoint.
         .anyRequest().authenticated()) //All other requests must be authenticated.
         // Send a 401 error response if user is not authentic.		 
         .exceptionHandling(exception -> exception.authenticationEntryPoint(authenticationEntryPoint)) //The authenticationEntryPoint is a custom entry point (often used to return a 401 Unauthorized response when the user is not authenticated).
         // no session management
         .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //This specifies that no HTTP sessions will be created or used by Spring Security.
         // filter the request and add authentication token		 
         .addFilterBefore(filter,  UsernamePasswordAuthenticationFilter.class)
         .build();
   }

   @Bean
   AuthenticationManager customAuthenticationManager() {
      return authentication -> new UsernamePasswordAuthenticationToken("randomuser123","password");
   }
}
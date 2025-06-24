package com.jankin.springsecurity6.config;

import com.jankin.springsecurity6.component.MySecurityFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity(debug = true)
public class SecurityConfig {


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http.csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable) //禁用默认登录页面
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/favicon.ico").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(mySecurityFilter() , UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exception -> exception
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setStatus(HttpStatus.FORBIDDEN.value());
                            response.setContentType("application/json;charset=UTF-8");
                            response.getWriter().write("{\"error\": \"无权限访问\"}");
                        }).authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(HttpStatus.UNAUTHORIZED.value());
                            response.setContentType("application/json;charset=UTF-8");
                            response.getWriter().write("{\"error\": \"未认证，请先登录\"}");
//                                    response.sendRedirect("/login");  //此处可重定向到登录页面
                        })
                )
                .build();
    }

    @Bean
    public MySecurityFilter mySecurityFilter() {
        return new MySecurityFilter();
    }


}

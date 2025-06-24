package com.jankin.springsecurity6.component;


import com.jankin.springsecurity6.service.MyUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class MySecurityFilter extends OncePerRequestFilter {

    private final String MY_COOKIE_NAME = "My_Cookie";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        MyUserDetailsService userDetailsService = new MyUserDetailsService();

        // 从请求中获取Cookie
        Cookie cookie = getCookie(request, MY_COOKIE_NAME);
        // 如果Cookie存在，则说明浏览器登录过，对请求放行
        if (cookie != null){
            System.out.println("cookie存在-----");
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetailsService.loadUserByUsername("admin"), null, userDetailsService.loadUserByUsername("admin").getAuthorities());
            usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            System.out.println(usernamePasswordAuthenticationToken.isAuthenticated() + "-----------");

        }else if ("/auth/login".equals( request.getServletPath())) { // 判断请求路径是否为登录路径，若为登录路径对登录用户进行判断
            System.out.println("进入了这里~~~");
            String queryString = request.getQueryString();
            if (queryString != null){
                String[] split = queryString.split("&");
                Map<String, String> paramater = new HashMap<>();

                for (String temp : split) {
                    String[] split1 = temp.split("=");
                    paramater.put(split1[0],split1[1]);
                }
                // 如果登录用户存在，则进行设置Cookie并放行
                if (paramater.get("userName").equals("admin") && paramater.get("password").equals("123456")) {
                    Cookie myCookie = new Cookie(MY_COOKIE_NAME, paramater.get("userName"));

                    myCookie.setHttpOnly(true); //禁止JavaScript访问
                    myCookie.setPath("/");  //设置Cookie适用路径
                    myCookie.setMaxAge(60 *60); //设置有效期为1小时
                    myCookie.setSecure(false);  // 若使用HTTPS，设置为true

                    System.out.println("创建了Cookie：" + myCookie);

                    response.addCookie(myCookie);
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetailsService.loadUserByUsername("admin"), null, userDetailsService.loadUserByUsername("admin").getAuthorities());
                    usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                }
            }


        }else {
            System.out.println("鉴权失败了！！！！");
        }
        filterChain.doFilter(request,response);


    }


    private Cookie getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return cookie;
                }
            }
        }
        return null;
    }



}

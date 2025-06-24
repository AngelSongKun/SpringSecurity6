# SpringSecurity6快速入门教程

SpringSecurity是Spring体系中的重要一部分，主要负责请求的鉴权与授权功能，本教程旨在快速入门SpringSecurity。

## 一、引入SpringSecurity依赖

通过maven引入`SpringSecurity`依赖。

```java
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

## 二、实现UserDetails接口

UserDetails是SpringSecurity中用来存储并获取用户信息的接口，可自定义实现UserDetails来进行存储自定义用户信息及权限信息；也可同时实现UserDetailsService接口，通过UserDetailsService接口的loadUserByUsername方法获取自定义的UserDetails。UserDetails是用来对请求接口放行授权时重要的类，可在授权时传入用户信息，并传入用户权限。此案例是自定义一个简单的用户信息，实际项目中可通过向数据库中获取用户信息及权限，或者通过从Redis中获取缓存的用户信息。

```java
public class MyUserDetails implements UserDetails {
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        List<String> roles = new ArrayList<String>();
        roles.add("admin");
        roles.add("user");

        List<SimpleGrantedAuthority> authorities = roles.stream()
                .map(SimpleGrantedAuthority::new) // 将字符串包装为 SimpleGrantedAuthority
                .toList();

        return authorities;
    }

    @Override
    public String getPassword() {
        String password = "123456";
        return password;
    }

    @Override
    public String getUsername() {
        String username = "admin";
        return username;
    }
}
```

## 三、手动创建`Filter`过滤器

手动创建一个Filter用来对请求进行鉴权操作；案例中首先对请求中的cookie进行判断，查看是否存有项目定义的cookie内容，若存在，则说明已进行授权，可对请求放行（在实际项目中，若存在cookie也需要对cookie中的内容进行判断，判断当前存储的cookie用户信息是否和登录的用户信息相符，若不相符，仍需要进行重新登录并生成新的cookie），若cookie不存在，则说明之前未进行登录过，此时判断拦截的接口是否为登录接口，若为登录接口，判断用户信息是否正确（实际项目中应从数据库中获取用户信息并进行对比是否正确），若用户信息正确，则生成一个包含用户信息的cookie并返回给浏览器并在SpringSecurity中设置授权认证并放行请求，若不是请求接口，则不做认证处理，会被SpringSecurity拦截到为未授权，无法访问信息，并跳转到登录页面。

```java
public class MySecurityFilter extends OncePerRequestFilter {

    private final String MY_COOKIE_NAME = "My_Cookie";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        MyUserDetailsService userDetailsService = new MyUserDetailsService();

        // 从请求中获取Cookie
        Cookie cookie = getCookie(request, MY_COOKIE_NAME);
        // 如果Cookie存在，则说明浏览器登录过，对请求放行
        if (cookie != null){
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetailsService.loadUserByUsername("admin"), null, userDetailsService.loadUserByUsername("admin").getAuthorities());
            usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        }else if ("/auth/login".equals( request.getServletPath())) { // 判断请求路径是否为登录路径，若为登录路径对登录用户进行判断
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
```

## 四、配置SpringSecurity配置类

自定义`SpringSecurity`配置类。配置类中有以下几点需要注意：

​	一）、老版本配置`SpringSecurity`直接继承了`WebSecurityConfigurerAdapter` 这个类，但是在SpringSecurity6版本之后将这个类移除了。

​	二）、还有一点就是在配置类中引入自定义Filter，采用将方法声明为Bean的方式，这样可以防止将自定义Filter整体设置为组件，从而被`SpringSecurity`和`SpringBoot`均配置为Bean引起请求时执行两次。

```java
@Configuration
@EnableWebSecurity
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
```

## 五、总结

SpringSecurity整体入门还是比较简单的，只要理清是在哪个方面进行安全防护即。SpringSecurity的原理就是自定义Filter过滤器，将每次请求进行判断是否符合预期，若不符合预期则进行拦截，若符合预期则进行放行。以下是我对SpringSecurity的理解流程图。

![image-20250624220841004](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20250624220841004.png)

package com.jankin.springsecurity6.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class UserController {

    @GetMapping("/login")
    public String login(String userName, String password) {

        return "XXX";
    }

    @GetMapping("/user")
    public String getUser(Long id) {

        return "1111";
    }
}

package com.rabitarochan.sandbox.jwt.controllers;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @RequestMapping("/")
    public String index(@AuthenticationPrincipal Authentication token) {
        String tokenString = "NULL";
        if (token != null) {
            tokenString = token.getPrincipal().toString();
        }
        return "It works! [" + tokenString + "]";
    }

}

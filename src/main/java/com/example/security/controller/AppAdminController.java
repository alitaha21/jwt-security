package com.example.security.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/admin/app")
public class AppAdminController {

    @GetMapping("/welcome")
    public ResponseEntity<String> welcome() {
        return new ResponseEntity<>("Welcome from ADMIN endpoint", HttpStatus.OK);
    }
}

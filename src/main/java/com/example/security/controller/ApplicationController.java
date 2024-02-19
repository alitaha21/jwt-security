package com.example.security.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/app")
public class ApplicationController {

    @GetMapping
    public ResponseEntity<String> welcome() {
        return new ResponseEntity<>("Welcome to JWT authentication app.", HttpStatus.OK);
    }

}

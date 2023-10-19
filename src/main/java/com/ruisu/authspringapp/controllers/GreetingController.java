package com.ruisu.authspringapp.controllers;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/greetings")
public class GreetingController {
    @GetMapping
    public ResponseEntity<String> sayHello(){
        return ResponseEntity.ok("APIからこんにちは");
    }

    @GetMapping("/say-goodbye")
    public ResponseEntity<String> sayGoodBye(){
        return ResponseEntity.ok("さようなら、また会いましょう");
    }


}

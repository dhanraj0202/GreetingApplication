package com.example.GreetingApp.Controller;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/greeting")
public class GreetingController {
    @GetMapping
    public String getGreeting() {
        return "Hello, this is a GET request!";
    }
}
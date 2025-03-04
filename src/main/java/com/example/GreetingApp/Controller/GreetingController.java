package com.example.GreetingApp.Controller;
import com.example.GreetingApp.Model.Greeting;
import com.example.GreetingApp.Service.GreetingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/greeting")
public class GreetingController {
    @GetMapping
    public String getGreeting() {
        return "Hello, this is a GET request!";
    }

    private final GreetingService greetingService;
    @Autowired
    public GreetingController(GreetingService greetingService) {
        this.greetingService = greetingService;
    }

    @GetMapping("/service")
    public String getGreetingServiceLayer() {
        return GreetingService.getGreetingMessage();
    }

    @GetMapping("/personalized")
    public String getGreeting(@RequestParam(required = false) String firstName,
                              @RequestParam(required = false) String lastName) {
        return greetingService.getGreetingMessage(firstName, lastName);
    }

    @GetMapping("/UC4")
    public String greet(@RequestParam(value = "firstName", required = false) String firstName,
                        @RequestParam(value = "lastName", required = false) String lastName) {
        String message = greetingService.getGreetingMessage(firstName, lastName);
        greetingService.saveGreetingMessage(message);
        return "{\"message\": \"" + message + "\"}";
    }

    @GetMapping("/UC5/{id}")
    public ResponseEntity<?> getGreetingById(@PathVariable Long id) {
        Optional<Greeting> greeting = greetingService.getGreetingById(id);
        if (greeting.isPresent()) {
            return ResponseEntity.ok(greeting.get());
        } else {
            return ResponseEntity.status(404)
                    .body("{\"error\": \"Greeting not found with ID: " + id + "\"}");
        }
    }
}
package com.example.GreetingApp.Controller;
import com.example.GreetingApp.Service.GreetingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

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


}
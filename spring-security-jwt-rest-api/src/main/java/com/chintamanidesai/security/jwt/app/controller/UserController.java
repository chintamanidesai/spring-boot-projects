package com.chintamanidesai.security.jwt.app.controller;

import com.chintamanidesai.security.jwt.app.model.User;
import com.chintamanidesai.security.jwt.app.service.UserServiceImpl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/users")
public class UserController {

    private final BCryptPasswordEncoder passwordEncoder;
    private final UserServiceImpl userService;

    public UserController(BCryptPasswordEncoder passwordEncoder, UserServiceImpl userService) {
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
    }

    @PostMapping("/singUp")
    public ResponseEntity<Void> signUp(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        this.userService.saveUser(user);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping
    public ResponseEntity<List<User>> getUsers() {
        final List<User> users = this.userService.findAllUsers();
        return ResponseEntity.ok(users);
    }

    @GetMapping(value = "/{userId}")
    public ResponseEntity<User> getUser(@PathVariable("userId") long userId) {
        final User user = this.userService.getUserById(userId);
        return ResponseEntity.ok(user);
    }

}

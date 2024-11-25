package com.example.demo.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.demo.modal.User;
import com.example.demo.repository.UserRepository;



@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    // Method to check if the user exists by sid and sub
    public boolean checkUserExistsBySidAndSub(String sid, String sub) {
        return userRepository.existsBySessionIdAndId(sid, sub);
    }

    public Optional<User> findById(String id) {
        return userRepository.findById(id);
    }
}

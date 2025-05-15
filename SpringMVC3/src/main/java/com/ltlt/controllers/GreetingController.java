/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.ltlt.controllers;

import com.ltlt.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 *
 * @author aicon
 */
@Controller
public class GreetingController {

    @Autowired
    private UserService userService;

    @RequestMapping("/")
    public String home(Model model) {
        return "home";  // Trả về file home.html
    }
}
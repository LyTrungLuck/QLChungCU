/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.ltlt.services.impl;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import com.ltlt.pojo.User;
import com.ltlt.repositories.UserRepository;
import com.ltlt.services.UserService;
import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

/**
 *
 * @author admin
 */
@Service("userDetailsService")
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepo;
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    @Autowired
    private Cloudinary cloudinary;

    @Override
    public User getUserByUsername(String username) {
        return this.userRepo.getUserByUsername(username);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User u = this.getUserByUsername(username);
        if (u == null) {
            throw new UsernameNotFoundException("Invalid username!");
        }

        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority(u.getRole()));
        
        return new org.springframework.security.core.userdetails.User(
                u.getUsername(), u.getPassword(), authorities);
    }

@Override
public User addUser(Map<String, String> params, MultipartFile avatar) {
    User u = new User();
    u.setFirstName(params.get("firstName")); // Họ
    u.setLastName(params.get("lastName"));  // Tên
    u.setUsername(params.get("username")); // Tên đăng nhập
    u.setPassword(this.passwordEncoder.encode(params.get("password"))); // Mã hoá mật khẩu
    u.setPhone(params.get("phone")); // Số điện thoại
    u.setEmail(params.get("email")); // Email

    // Đặt vai trò (nếu không có, mặc định là RESIDENT)
    String role = params.getOrDefault("role", "RESIDENT");
    u.setRole(role.equals("ADMIN") ? "ADMIN" : "RESIDENT");

    // Đặt trạng thái kích hoạt (nếu không có, mặc định là TRUE)
    u.setActive(Boolean.parseBoolean(params.getOrDefault("active", "true")));

    // Xử lý avatar
    if (avatar != null && !avatar.isEmpty()) {
        try {
            Map res = cloudinary.uploader().upload(avatar.getBytes(), ObjectUtils.asMap("resource_type", "auto"));
            u.setAvatar(res.get("secure_url").toString());
        } catch (IOException ex) {
            Logger.getLogger(UserServiceImpl.class.getName()).log(Level.SEVERE, "Error while uploading avatar", ex);
        }
    }

    // Lưu người dùng vào cơ sở dữ liệu
    try {
        return this.userRepo.addUser(u);
    } catch (Exception ex) {
        Logger.getLogger(UserServiceImpl.class.getName()).log(Level.SEVERE, "Error while saving user", ex);
        throw new RuntimeException("Could not create user. Please check your input.");
    }
}
      

    @Override
    public boolean authenticate(String username, String password) {
        return this.userRepo.authenticate(username, password);
    }

}

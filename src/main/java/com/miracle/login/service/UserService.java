package com.miracle.login.service;

import com.miracle.login.beans.Role;
import com.miracle.login.beans.User;
import com.miracle.login.repository.RoleRepository;
import com.miracle.login.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@Transactional
public class UserService implements UserServiceImpl{
	 @Autowired
	 private UserRepository userRepository;
	 
	 @Autowired
	 private RoleRepository roleRepository;
	 
	 public User findUserByEmail(String email) {
	       User user= userRepository.findByEmail(email);
	        return user;
	 }
	 
	@Override
	public List<Role> getAllRoles() {
			
		return roleRepository.findAll();
			
	}

	@Override
	public List<User> getAllUsers() {
		// TODO Auto-generated method stub
		return userRepository.findAll();
	}
	public Optional<User> getUserInfo(String id){
		return userRepository.findById(id);
	}
	@Override
	public User findByName(String username) {
		User user= userRepository.findByName(username);
		return user;
	}

	@Override
	public Optional<User> getAllRolesFromId(String id) {
		return userRepository.findByRoleId(id);
	}

	@Override
	public Optional<User> findByResetToken(String token) {
		return userRepository.findByResetToken(token);	
	}
	
}


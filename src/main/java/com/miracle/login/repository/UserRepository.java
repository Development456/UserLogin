package com.miracle.login.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import com.miracle.login.beans.User;
@Repository
public interface UserRepository extends MongoRepository<User, String> {
	  Optional<User> findByUsername(String username);
	  
	  @Query("{username: ?0}")
	  User findByName(String username);

	  Boolean existsByUsername(String username);

	  Boolean existsByEmail(String email);
	  
	  User findByEmail(String email);
	  
	  Optional<User> findById(String id);

}

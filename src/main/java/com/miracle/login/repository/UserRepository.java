package com.miracle.login.repository;

import com.miracle.login.beans.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface UserRepository extends MongoRepository<User, String> {
	  Optional<User> findByUsername(String username);
	  
	  @Query("{username: ?0}")
	  User findByName(String username);

	  Boolean existsByUsername(String username);

	  Boolean existsByEmail(String email);
	  
	  @Query("{email: ?0}")
	  User findByEmail(String email);
	  
	  @Query("{token: ?0}")
	  Optional<User> findByResetToken(String token);

	  
	  @Query("{id: ?0}")
	  Optional<User> findById(String id);

	  @Query(value="{id: ?0}", fields= "{roles:1}")
	  Optional<User> findByRoleId(String id);

	
}

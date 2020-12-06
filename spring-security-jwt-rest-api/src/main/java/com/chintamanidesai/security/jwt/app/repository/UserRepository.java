package com.chintamanidesai.security.jwt.app.repository;

import com.chintamanidesai.security.jwt.app.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    User findByUsername(String username);
}

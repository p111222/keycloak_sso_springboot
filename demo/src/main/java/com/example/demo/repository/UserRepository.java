package com.example.demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.example.demo.modal.User;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

        // Optional<User> findByUserEmail(String userEmail);

    @Query("SELECT COUNT(u) > 0 FROM User u WHERE u.sid = :sid AND u.id = :sub")
    boolean existsBySessionIdAndId(@Param("sid") String sid, @Param("sub") String sub);

}

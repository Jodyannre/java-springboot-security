package com.app.repository;

import com.app.persistence.entity.UserEntity;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<UserEntity, Long> {

    Optional<UserEntity> findUserEntityByUsername(String username);

    //Con query
    /*
    @Query("SELECT u FROM UserEntity u WHERE u.username = ?")
    Optional<UserEntity> finduser(String userName);

     */
}

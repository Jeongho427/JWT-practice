package com.security.springjwt.repository;


import com.security.springjwt.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    Boolean existsByUsername(String username);

    //username 받아 DB 테이블에서 회원을 조회하는 메소드
    UserEntity findByUsername(String username);
}

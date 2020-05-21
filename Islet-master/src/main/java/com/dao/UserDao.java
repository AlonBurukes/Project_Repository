package com.dao;

import com.entities.User;

import java.util.List;

public interface UserDao {
    public User getUserByUserName(String name);
}

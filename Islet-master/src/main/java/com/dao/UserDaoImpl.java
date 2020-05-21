package com.dao;

import com.entities.User;

import java.util.List;

public class UserDaoImpl extends BaseDao implements UserDao{
    private static UserDaoImpl userDao;
    private UserDaoImpl(){

    }
    public static UserDaoImpl getUserDaoImpl(){
        if(userDao==null){
            userDao=new UserDaoImpl();
        }
        return userDao;
    }
    @Override
    public User getUserByUserName(String name) {
        return null;
    }
}

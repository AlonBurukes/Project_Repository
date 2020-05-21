package com.entities;

public class User {
    private int id;
    private String user;
    private String pass;


    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUsername() {
        return user;
    }

    public void setUsername(String username) {
        this.user = username;
    }

    public String getPassword() {
        return pass;
    }

    public void setPassword(String password) {
        this.pass = password;
    }

    public User(int id, String username, String password) {
        this.id = id;
        this.user = username;
        this.pass = password;
    }

    public User(String user, String pass) {
        this.user = user;
        this.pass = pass;
    }

    public User() {
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", user='" + user + '\'' +
                ", pass='" + pass + '\'' +
                '}';
    }
}

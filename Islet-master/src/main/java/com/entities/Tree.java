package com.entities;

public class Tree {
    private int userName;
    private String note;
    private int like;

    public Tree(int userName, String note, int like) {
        this.userName = userName;
        this.note = note;
        this.like = like;
    }

    public int getUserName() {
        return userName;
    }

    public void setUserName(int userName) {
        this.userName = userName;
    }

    public String getNote() {
        return note;
    }

    public void setNote(String note) {
        this.note = note;
    }

    public int getLike() {
        return like;
    }

    public void setLike(int like) {
        this.like = like;
    }
}

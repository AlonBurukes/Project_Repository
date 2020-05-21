package com.entities;

import com.alibaba.fastjson.annotation.JSONField;

public class Quote {
    @JSONField(serialize=false)
    private int id;
    @JSONField(serialize=true)
    private String author;
    @JSONField(serialize=true)
    private String quote;

    public Quote(int id, String quote) {
        this.id = id;
        this.quote = quote;
    }

    public Quote(String author, String quote) {
        this.author = author;
        this.quote = quote;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getQuote() {
        return quote;
    }

    public void setQuote(String quote) {
        this.quote = quote;
    }

    public String getAuthor() {
        return author;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    @Override
    public String toString() {
        return "Quote{" +
                "id=" + id +
                ", author='" + author + '\'' +
                ", quote='" + quote + '\'' +
                '}';
    }
}

package com.dao;

import com.entities.Quote;

import java.sql.SQLException;

public interface QuoteDao {
    //quote只读
    public Quote getQuoteById(int id) throws SQLException;
}

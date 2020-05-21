package com.service;

import com.entities.Quote;

import java.sql.SQLException;
import java.util.ArrayList;

public interface QuotePasser {
    public ArrayList<Quote> passQuote() throws SQLException;
}

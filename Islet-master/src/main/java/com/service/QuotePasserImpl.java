package com.service;

import com.dao.QuoteDaoImpl;
import com.entities.Quote;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Random;

public class QuotePasserImpl implements QuotePasser{
    private static QuotePasserImpl quotePasser;
    private QuotePasserImpl(){

    }
    public static QuotePasserImpl getInstance(){
        if(quotePasser==null){
            quotePasser=new QuotePasserImpl();
        }
        return quotePasser;
    }
    @Override
    public ArrayList<Quote> passQuote() throws SQLException {
        //调用dao类中的方法
        QuoteDaoImpl quoteDao=QuoteDaoImpl.getInstance();
        ArrayList<Quote> quotes=new ArrayList<>();
        for(int i=0;i<3;i++){
            quotes.add(quoteDao.getQuoteById(new Random().nextInt(quoteDao.getTotal())+1));
        }
        return quotes;
    }
}

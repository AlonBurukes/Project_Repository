package com.dao;

import com.entities.Quote;

import java.sql.ResultSet;
import java.sql.SQLException;

public class QuoteDaoImpl extends BaseDao implements QuoteDao{
    private static QuoteDaoImpl quoteDao;

    private int total;

    private QuoteDaoImpl() throws SQLException {
        Object[] params={};
        ResultSet resultSet=this.ExecuteQuery("select count(*) from main_quote;",params);
        while(rs.next()) {
            this.total = resultSet.getInt(1);
        }
    }
    public static QuoteDaoImpl getInstance() throws SQLException {
        if(quoteDao==null){
            quoteDao=new QuoteDaoImpl();
        }
        return quoteDao;
    }

    /**
     * 根据id获得quote对象的方法
     * @param id
     * @return
     * @throws SQLException
     */
    @Override
    public Quote getQuoteById(int id) throws SQLException {
        Quote quote=null;
        String sql="select * from main_quote where id=?;";
        Object[] params={id};
        rs=this.ExecuteQuery(sql,params);
        while(rs.next()){
            String author=rs.getString(2);
            String content=rs.getString(3);
            quote=new Quote(author,content);
        }
        return quote;
    }

    public int getTotal() {
        return total;
    }

    public void setTotal(int total) {
        this.total = total;
    }
}

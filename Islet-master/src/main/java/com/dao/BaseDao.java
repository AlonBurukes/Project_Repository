package com.dao;


import org.apache.log4j.Logger;

import java.io.IOException;
import java.sql.*;
import java.util.Properties;


public class BaseDao {


    Connection conn=null;
    PreparedStatement ps=null;
    ResultSet rs=null;

    //获取链接
    public void getConnection(){
        Properties properties=new Properties();
        try {
            properties.load(Thread.currentThread().getContextClassLoader().getResourceAsStream("db.properties"));
            // 数据库驱动
            String DRIVER_CLASS = properties.getProperty("DRIVER_CLASS");
            // 数据库连接地址
            String DB_URL = properties.getProperty("DB_URL");
            // 数据库用户名称
            String DB_USER = properties.getProperty("DB_USER");
            // 数据库用户密码
            String DB_PASSWORD = properties.getProperty("DB_PASSWORD");

            Class.forName(DRIVER_CLASS);
            conn=DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            System.out.println("success connected to db");
        } catch (IOException | ClassNotFoundException | SQLException e) {
            e.printStackTrace();
        }
    }



    //获取链接
//    public boolean getConnection(){
//        String driver="com.mysql.cj.jdbc.Driver";
//        String url="jdbc:mysql://localhost:3306/quotes";
//        String username="zj";
//        String password="123456";
//        try{
//            Class.forName(driver);
//            conn= DriverManager.getConnection(url,username,password);
//        }catch (SQLException e){
//            e.printStackTrace();
//        }catch (ClassNotFoundException e){
//            e.printStackTrace();
//        }
//        return true;
//
//    }

    //关闭资源
    public boolean closeResource(){
        if(null!=rs){
            try{
                rs.close();
            }catch (SQLException e){
                e.printStackTrace();
            }
        }

        if(null!=ps){
            try {
                ps.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }

        if(null!=conn){
            try {
                conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        return true;
    }

    //增删改操作
    public int executeUpdate(String sql,Object[] params){
        int updateRows=0;
        if(this.conn==null){
            this.getConnection();
        }

        //获得sql语句
        try {
            ps=conn.prepareStatement(sql);
            //给占位符的赋值
            for(int i=0;i<params.length;i++){
                ps.setObject(i+1,params[i] );
            }
            //执行 增删改,返回影响的行数
            updateRows=ps.executeUpdate();

        } catch (SQLException | NullPointerException e) {
            // TODO Auto-generated catch block
            if(e instanceof NullPointerException){
                //如果是空指针异常
                e.printStackTrace();

            }else {
                //如果是SQL异常
                e.printStackTrace();
            }

        }
        return updateRows;
    }

    //查询 全部信息 或者指定部分信息
    public ResultSet ExecuteQuery(String sql ,Object [] params){
        if(conn==null){
            this.getConnection();
        }
        try {
            ps=conn.prepareStatement(sql);
            //给占位符赋值
            for(int i=0;i<params.length;i++){
                ps.setObject(i+1, params[i]);
            }
            // 执行查询，返回值是ResultSet型的
            rs=ps.executeQuery();
        } catch (SQLException | NullPointerException e) {
            // TODO Auto-generated catch block
            if(e instanceof NullPointerException){
                //如果是空指针异常
                e.printStackTrace();
            }else {
                //如果是SQL异常
                e.printStackTrace();
            }

        }
        return rs;
    }

}

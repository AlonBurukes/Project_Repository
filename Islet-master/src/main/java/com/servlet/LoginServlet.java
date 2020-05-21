package com.servlet;


import com.service.UserCheckerImpl;


import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;

/**
 * 登录验证的Servlet
 */
@WebServlet(name = "LoginServlet",urlPatterns = "/login")
public class LoginServlet extends HttpServlet {
    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        //设置输入格式为UTF-8
        resp.setCharacterEncoding("UTF-8");
        //设置内容类型为UTF-8
        resp.setContentType("application/json;charset=utf-8");
        //获得打印流对象
        PrintWriter out = resp.getWriter();
        //此打印流对象可向浏览器输出信息

        //判断用户是否存在
        boolean exist=UserCheckerImpl.getInstance().checkUser(req);

        //如果存在状态码200 不存在403
        if(exist){
            resp.setStatus(403);
        }else {
            resp.setStatus(200);
        }

        //清理打印流
        out.flush();
        //冲洗
    }
}

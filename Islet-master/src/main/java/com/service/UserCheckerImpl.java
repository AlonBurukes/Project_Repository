package com.service;

import com.alibaba.fastjson.JSONObject;
import com.dao.UserDaoImpl;
import com.entities.User;
import com.service.util.ParseReqToJson;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class UserCheckerImpl implements UserChecker{
    private static UserCheckerImpl userChecker;
    private UserCheckerImpl(){

    }
    public static UserCheckerImpl getInstance(){
        if(userChecker==null){
            userChecker=new UserCheckerImpl();
        }
        return userChecker;
    }

    @Override
    public boolean checkUser(HttpServletRequest req) throws IOException {
        UserDaoImpl userDao=UserDaoImpl.getUserDaoImpl();
        //解析Post，转化为json字符串
        String userJson=ParseReqToJson.parseReq(req);
        //将json字符串转化为JSONObject
        JSONObject obj=JSONObject.parseObject(userJson);
        //新建实体类
        User user=new User((String) obj.get("user"),(String)obj.get("pass"));
        //数据库操作
        User realUser=userDao.getUserByUserName(user.getUsername());
        //判断
        if(realUser.getPassword().equals(user.getPassword())){
            return true;
        }else {
            return false;
        }
    }
}

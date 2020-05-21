package com.service;

import com.entities.User;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public interface UserChecker {
    public boolean checkUser(HttpServletRequest req) throws IOException;
}

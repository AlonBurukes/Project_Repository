package com.service.util;

import javax.servlet.http.HttpServletRequest;
import java.io.DataInputStream;
import java.io.*;


public class ParseReqToJson {
    public static String parseReq(HttpServletRequest req) throws IOException {
        int totalbytes = req.getContentLength();
        // 容纳请求消息实体的字节数组
        byte[] dataOrigin = new byte[totalbytes];
        DataInputStream in = new DataInputStream(req.getInputStream());
        in.readFully(dataOrigin); // 根据长度，将消息实体的内容读入字节数组dataOrigin中
        in.close(); // 关闭数据流
        return new String(dataOrigin);
    }
}

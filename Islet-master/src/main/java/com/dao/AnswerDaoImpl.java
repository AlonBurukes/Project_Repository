package com.dao;

import com.entities.Answer;

public class AnswerDaoImpl extends BaseDao implements AnswerDao{
    private static AnswerDaoImpl answerDao;
    public static AnswerDaoImpl getInstance(){
        if(answerDao==null){
            answerDao=new AnswerDaoImpl();
        }
        return answerDao;
    }
    private AnswerDaoImpl(){

    }

    @Override
    public Answer getAnswerByid() {
        //根据id获得Answer

        return null;
    }
}

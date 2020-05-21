package com.dao;

import com.entities.Tree;

public interface TreeDao {
    public int insertNote(Tree tree);
    public Tree getTreeNoteByid();
}

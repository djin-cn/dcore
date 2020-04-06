package me.djin.dcore.frame.common;

import tk.mybatis.mapper.common.Mapper;

/**
 * @author djin 
 * 
 * 基础数据访问类，提供数据库基础访问操作 <br />
 * 不包含批量添加、删除操作
 * @param <T>
 */
public interface CurdBaseDao<T> extends Mapper<T> {

}

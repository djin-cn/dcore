package me.djin.dcore.frame.common;

import tk.mybatis.mapper.additional.idlist.IdListMapper;
import tk.mybatis.mapper.additional.insert.InsertListMapper;

/**
 * @author djin
 * 
 *         基础数据访问类，提供数据库基础访问操作 <br />
 *         包含批量添加和删除操作
 * @param <T>
 */
public interface CurdDao<T> extends CurdBaseDao<T>, IdListMapper<T, Long>, InsertListMapper<T> {

}

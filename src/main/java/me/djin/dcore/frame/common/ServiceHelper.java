package me.djin.dcore.frame.common;

import org.apache.commons.lang3.StringUtils;

import me.djin.dcore.util.spring.SpringContextUtil;

/**
 * 服务帮助类
 * @author djin
 *
 */
class ServiceHelper {
	/**
	 * 获取DAO实例
	 * @param t 实体类
	 * @return
	 */
	@SuppressWarnings("unchecked")
	static <T> CurdBaseDao<T> getInstance(T t){
		String beanName =StringUtils.uncapitalize(t.getClass().getSimpleName())+"Dao";
		return (CurdBaseDao<T>)SpringContextUtil.getBean(beanName);
	}
	
	/**
	 * 获取DAO实例
	 * @param clazz 实体类
	 * @return
	 */
	@SuppressWarnings("unchecked")
	static <T> CurdBaseDao<T> getInstance(Class<T> clazz){
		String beanName =StringUtils.uncapitalize(clazz.getSimpleName())+"Dao";
		return (CurdBaseDao<T>)SpringContextUtil.getBean(beanName);
	}
}

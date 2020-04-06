package me.djin.dcore.util;

import me.djin.dcore.util.spring.SpringContextUtil;

/**
 * @author djin
 * 公共对象实例工厂，主要用于解耦第三方框架
 */
public class CommonFactory {
	public static Object getBean(Class<?> clazz) {
		SpringContextUtil.getBean(clazz);
		return null;
	}
	
	public static Object getBean(String beanId) {
		return SpringContextUtil.getBean(beanId);
	}
}

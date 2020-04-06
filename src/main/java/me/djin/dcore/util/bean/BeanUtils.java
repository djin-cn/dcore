/**
 * 
 */
package me.djin.dcore.util.bean;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import net.sf.cglib.beans.BeanCopier;
import net.sf.cglib.core.Converter;

/**
 * @author djin 基于cglib实现的Bean对象操作，替代Apache和Spring提供的BeanUtils类。
 */
public class BeanUtils {
	/**
	 * 复制Bean对象
	 * 
	 * 根据属性名称和类型将源对象的属性值复制到目标对象，类型不一致时，会自动对以下类型进行转换：Date和Long类型; 字符串和数字、字节、布尔
	 * 
	 * 调用示例:
	 * <pre>
	 * BeanUtils.copy(源对象, 目标对象);
	 * </pre>
	 * 
	 * @param orig
	 * @param dest
	 * @return
	 */
	public static <T> T copy(Object orig, Class<T> dest){
		return copy(orig, dest, (value, target, context) -> {
			//如果value值为NULL，直接返回
			if(value == null) {
				return value;
			}
			boolean isBooleanOfTarget = target == Long.class || target == Long.TYPE;
			// Date转换为时间戳
			if (value instanceof Date && isBooleanOfTarget) {
				return ((Date) value).getTime();
			}
			// 时间戳转Date
			if (value instanceof Long && target == Date.class) {
				return new Date((Long) value);
			}
			//其它类型转String
			if(target == String.class && !(value instanceof String)) {
				return value.toString();
			}
			// String转数字、字节、布尔
			if (value instanceof String) {
				String numberValue = value.toString();
				if("".equals(numberValue)) {
					numberValue = "0";
				}
				if (target == Long.class || target == Long.TYPE) {
					return Long.valueOf(numberValue.toString());
				}
				if (target == Integer.class || target == Integer.TYPE) {
					return Integer.valueOf(numberValue.toString());
				}
				if (target == Short.class || target == Short.TYPE) {
					return Short.valueOf(numberValue.toString());
				}
				if (target == Float.class || target == Float.TYPE) {
					return Float.valueOf(numberValue.toString());
				}
				if (target == Double.class || target == Double.TYPE) {
					return Double.valueOf(numberValue.toString());
				}
				if (target == Byte.class || target == Byte.TYPE) {
					return Byte.valueOf(numberValue.toString());
				}
				if (target == Boolean.class || target == Boolean.TYPE) {
					return Boolean.valueOf(numberValue.toString());
				}
			}
			return value;
		});
	}
	
	/**
	 * 复制Bean对象, 内部调用copy(Object, Class<T>)实现
	 * 
	 * 默认非同名字段相互之间不会进行复制，某些不同类型的字段之间也不会进行复制，可通过回调函数手动复制
	 * 
	 * 调用示例:
	 * <pre>
	 * BeanUtils.copy(源对象, 目标对象, (orig, target)->{return target;});
	 * </pre>
	 * 
	 * @param orig
	 * @param dest
	 * @param callback
	 * @return
	 */
	public static <T> T copy(Object orig, Class<T> dest, BeanCopyCallback<T> callback){
		T t  = copy(orig, dest);
		t = callback.call(orig, t);
		return t;
	}

	/**
	 * 复制Bean对象。
	 * 
	 * 根据converter转换器将orig对象的属性值复制到dest对象，
	 * 
	 * 如果onverter为null，表示采用默认的方式复制，默认复制规则：复制orig与dest相同属性名称且相同类型的属性值。
	 * 
	 * 调用示例：
	 * 
	 * <pre>
	 * BeanUtils.copy(源对象, 目标对象, (origValue, targetClass, context) -> {
	 * 	return value;
	 * });
	 * </pre>
	 * 
	 * @param orig
	 *            复制源
	 * @param dest
	 *            复制目标
	 * @param converter
	 *            转换器，用于将orig对象复制到dest对象;
	 * @return
	 */
	public static <T> T copy(Object orig, Class<T> dest, Converter converter) {
		if(orig == null) {
			return null;
		}
		boolean useConverter = converter != null;
		BeanCopier copier = BeanCopier.create(orig.getClass(), dest, useConverter);
		T to = null;
		try {
			to = dest.newInstance();
		} catch (InstantiationException | IllegalAccessException e) {
			throw new RuntimeException("Bean转换失败", e);
		}
		copier.copy(orig, to, converter);
		return to;
	}

	/**
	 * 复制Bean集合对象, 内部调用copy(Object, Class<T>)实现
	 * 
	 * @param list
	 * @param dest
	 * @see BeanUtils.copy(Object orig, Class<T> dest)
	 * @return
	 */
	public static <T> List<T> copyList(Collection<? extends Object> list, Class<T> dest) {
		if(list == null || list.isEmpty()) {
			return null;
		}
		List<T> tlist = new ArrayList<>();
		for (Object obj : list) {
			T t = copy(obj, dest);
			tlist.add(t);
		}
		return tlist;
	}
	
	/**
	 * 复制Bean集合对象, 内部调用copy(Object, Class<T>, Callback)实现
	 * @param list
	 * @param dest
	 * @param callback
	 * @return
	 */
	public static <T> List<T> copyList(Collection<? extends Object> list, Class<T> dest, BeanCopyCallback<T> callback) {
		if(list == null || list.isEmpty()) {
			return null;
		}
		List<T> tlist = new ArrayList<>();
		for (Object obj : list) {
			T t = copy(obj, dest, callback);
			tlist.add(t);
		}
		return tlist;
	}
	
	/**
	 * 复制Bean集合对象, 内部调用copy(Object, Class<T>, Converter)实现
	 * @param list
	 * @param dest
	 * @param converter
	 * @see BeanUtils.copy(Object orig, Class<T> dest, Converter converter)
	 * @return
	 */
	public static <T> List<T> copyList(Collection<? extends Object> list, Class<T> dest, Converter converter) {
		if(list == null || list.isEmpty()) {
			return null;
		}
		List<T> tlist = new ArrayList<>();
		for (Object obj : list) {
			T t = copy(obj, dest, converter);
			tlist.add(t);
		}
		return tlist;
	}
}

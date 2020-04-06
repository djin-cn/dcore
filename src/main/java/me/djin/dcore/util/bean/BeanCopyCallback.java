package me.djin.dcore.util.bean;

/**
 * @author djin
 */
public interface BeanCopyCallback<T> {
	/**
	 * 回调方法，用于转换完成之后进行其他处理，如不同名字段的值拷贝等
	 * 
	 * @param orig
	 * @param dest
	 * @return
	 */
	T call(Object orig, T dest);
}
/**
 * 
 */
package me.djin.dcore.redis;

import java.util.Collection;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;

/**
 * @author djin
 * 缓存接口
 * 
 * 缓存键生成规则建议:
 * 1: 单个Bean缓存建议:服务名+Bean类名+主键
 * 2: Map/Collection缓存建议:服务名+Service类名+方法名+条件
 * 缓存策略建议:
 * 1: 不建议单个键值对存储, 建议通过Map统一存储; 如: 系统配置项
 * 2: 建议给所有缓存设置过期时间, 单位统一为10分钟的倍数, 常量类型的配置可以设置较长的过期时间
 */
public interface Cacheable {
	/**
	 * 设置String缓存
	 * @param key 缓存键
	 * @param value 缓存值
	 * @param timeout 过期时间
	 * @param unit 过期时间单位
	 */
	void set(String key, Object value, long timeout, TimeUnit unit);
	/**
	 * 设置Hash缓存
	 * 
	 * @param key 缓存键
	 * @param value 缓存对象, 类型可以Map对象或者JavaBean对象
	 * @param timeout 过期时间
	 * @param unit 过期时间单位
	 */
	<T> void setMap(String key, T value, long timeout, TimeUnit unit);
	/**
	 * 设置List缓存
	 * @param key 缓存键
	 * @param value 缓存对象
	 * @param timeout 过期时间
	 * @param unit 过期时间单位
	 */
	<T> void setList(String key, Collection<T> value, long timeout, TimeUnit unit);
	/**
	 * 获取缓存
	 * @param key
	 * @return
	 */
	Object get(String key);
	/**
	 * 获取Hash缓存
	 * @param key 缓存键
	 * @param clazz 缓存转换类型
	 * @return
	 */
	<T> T getObject(String key, Class<T> clazz);
	/**
	 * 获取Hash缓存
	 * @param key
	 * @return
	 */
	HashMap<String, Object> getMap(String key);
	/**
	 * 获取缓存列表
	 * @param key 缓存键
	 * @param clazz 缓存转换类型
	 * @return
	 */
	<T> Collection<T> getList(String key, Class<T> clazz);
	/**
	 * 删除缓存
	 * @param key 缓存键
	 */
	void delete(String key);
}

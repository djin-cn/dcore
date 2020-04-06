/**
 * 
 */
package me.djin.dcore.redis;

import java.util.function.Function;

/**
 * @author djin
 * 
 * redis 分布式锁
 */
public interface RedisLockable {
	/**
	 * 加锁资源
	 * <pre>
	 * RedisLockable lockable = new ...();
	 * String key = "LOCK_KEY";
	 * String value = UUID.randomUUID().toString();
	 * int expire = 30;
	 * boolean lockFlag = false;
	 * do {
	 *     lockFlag = lockable.lock(key, value, expire);
	 *     if(lockFlag) {
	 *         //doSomething
	 *     }
	 * } while (!lockFlag);
	 * </pre>
	 * @param key KEY
	 * @param value 必须唯一, 主要作用为在解锁时防止误删除, 建议使用UUID.randomUUID().toString()生成
	 * @param expire 锁过期时间, 单位为秒, 一般要设置大于业务的实际执行时间; 如果小于等于0, 则 默认设置为30秒
	 * @return true表示成功加锁, false表示未成功加锁
	 */
	boolean lock(String key, String value, long expire);
	/**
	 * 解锁资源
	 * @param key KEY
	 * @param value 唯一值, 必须与{@link #lock(String, String, long)}方法的value值一致, 否则无法主动解锁
	 * 
	 */
	void unlock(String key, String value);
	/**
	 * 独占锁同步调用function参数指定的匿名方法并返回R结果
	 * 
	 * 此方法可能会导致执行超时, 因为此方法会一直获取锁直到获取成功, 然后执行function
	 * <pre>
	 * String key = "LOCK_KEY";
	 * int expire = 30;
	 * String result = lockable.execute(key, expire, "hello", param->{
	 *     return param+"result";
	 * });
	 * </pre>
	 * @param key KEY
	 * @param expire 锁过期时间, 单位为秒, 一般要设置大于业务的实际执行时间; 如果小于等于0, 则 默认设置为30秒
	 * @param parameter 传入function匿名方法的参数, 如果不需要传递参数可以指定为NULL
	 * @param function 实际调用的逻辑代码, 此参数不能为NULL, 因为为NULL没有意义
	 * @return R
	 */
	<T, R> R execute(String key, long expire, T parameter, Function<T, R> function);
	/**
	 * 独占锁同步调用function参数指定的匿名方法并返回R结果
	 * 
	 * 此方法会尝试获取锁(只获取一次), 如果获取成功, 则执行function, 如果获取失败则直接返回NULL
	 * <pre>
	 * String key = "LOCK_KEY";
	 * int expire = 30;
	 * String result = lockable.execute(key, expire, "hello", param->{
	 *     return param+"result";
	 * });
	 * </pre>
	 * @param key KEY
	 * @param expire 锁过期时间, 单位为秒, 一般要设置大于业务的实际执行时间; 如果小于等于0, 则 默认设置为30秒
	 * @param parameter 传入function匿名方法的参数, 如果不需要传递参数可以指定为NULL
	 * @param function 实际调用的逻辑代码, 此参数不能为NULL, 因为为NULL没有意义
	 * @return R
	 */
	<T, R> R tryExecute(String key, long expire, T parameter, Function<T, R> function);
}

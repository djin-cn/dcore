/**
 * 
 */
package me.djin.dcore.redis;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import org.apache.commons.beanutils.BeanUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;

import com.alibaba.fastjson.JSON;

import net.sf.cglib.beans.BeanMap;

/**
 * @author djin 
 * 
 * Redis缓存
 */
public class RedisCacheable implements Cacheable, RedisLockable {
	private static final Logger LOG = LoggerFactory.getLogger(RedisCacheable.class);
	private RedisTemplate<String, Object> redis;

	public RedisCacheable(RedisTemplate<String, Object> redisTemplate) {
		this.redis = redisTemplate;
	}

	@Override
	public void set(String key, Object value, long timeout, TimeUnit unit) {
		try {
			if (timeout > 0 && unit != null) {
				redis.opsForValue().set(key, value, timeout, unit);
			} else {
				redis.opsForValue().set(key, value);
			}
		} catch (Exception e) {
			LOG.error("cannot set value to redis, key=" + key, e);
		}
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public <T> void setMap(String key, T value, long timeout, TimeUnit unit) {
		if (value == null) {
			return;
		}
		Map map = null;
		if (value instanceof Map) {
			map = (Map) value;
		} else {
			map = BeanMap.create(value);
		}
		try {
			redis.opsForHash().putAll(key, map);
			if (timeout > 0 && unit != null) {
				redis.expire(key, timeout, unit);
			}
		} catch (Exception e) {
			LOG.error("cannot set hash value to redis, key=" + key, e);
		}
	}

	@Override
	public <T> void setList(String key, Collection<T> value, long timeout, TimeUnit unit) {
		Collection<String> list = new ArrayList<String>();
		for (Object object : value) {
			String tmp = JSON.toJSONString(object);
			list.add(tmp);
		}
		try {
			redis.opsForList().rightPushAll(key, list.toArray());
			if (timeout > 0 && unit != null) {
				redis.expire(key, timeout, unit);
			}
		} catch (Exception e) {
			LOG.error("cannot set list value to redis, key=" + key, e);
		}
	}

	@Override
	public Object get(String key) {
		try {
			return redis.opsForValue().get(key);
		} catch (Exception e) {
			LOG.error("cannot get value from redis, key=" + key, e);
			return null;
		}
	}

	@Override
	public <T> T getObject(String key, Class<T> clazz) {
		HashMap<String, Object> map = getMap(key);
		if (map == null) {
			return null;
		}
		T object = null;
		try {
			object = clazz.newInstance();
			BeanUtils.populate(object, map);
		} catch (InstantiationException | IllegalAccessException e) {
			LOG.error("cannot create instance of " + clazz.getName(), e);
		} catch (InvocationTargetException e) {
			LOG.error("cannot be cast redis hashmap to " + clazz.getName(), e);
		}
		return object;
	}

	@Override
	public HashMap<String, Object> getMap(String key) {
		Map<Object, Object> map = null;
		try {
			map = redis.opsForHash().entries(key);
		} catch (Exception e) {
			LOG.error("cannot get hash value from redis, key=" + key, e);
			return null;
		}
		if (map == null) {
			return null;
		}
		HashMap<String, Object> result = new HashMap<>(map.entrySet().size());
		for (Map.Entry<Object, Object> entry : map.entrySet()) {
			result.put(entry.getKey().toString(), entry.getValue());
		}
		return result;
	}

	@Override
	public <T> Collection<T> getList(String key, Class<T> clazz) {
		List<Object> list = null;
		try {
			list = redis.opsForList().range(key, 0, -1);
		} catch (Exception e) {
			LOG.error("cannot get list value from redis, key=" + key, e);
			return null;
		}
		if (list == null) {
			return null;
		}
		List<T> result = new ArrayList<>();
		for (Object object : list) {
			T instance = JSON.parseObject(object.toString(), clazz);
			result.add(instance);
		}
		return result;
	}

	@Override
	public void delete(String key) {
		try {
			redis.delete(key);
		} catch (Exception e) {
			LOG.error("cannot delete value from redis, key=" + key, e);
		}
	}

	@Override
	public boolean lock(String key, String value, long expire) {
		if(value == null) {
			throw new NullPointerException("redis lock value must no be null");
		}
		if(expire <= 0) {
			expire = 30;
		}
		Boolean flag = null;
		try {
			flag = redis.opsForValue().setIfAbsent(key, value, expire, TimeUnit.SECONDS);
		} catch (Exception e) {
			LOG.error("cannot set lock value to redis, key=" + key, e);
		}
		return Boolean.TRUE.equals(flag);
	}

	@Override
	public void unlock(String key, String value) {
		if(value == null) {
			throw new NullPointerException("redis lock value must no be null");
		}
		Object lockValue = redis.opsForValue().get(key);
		if(value.equals(lockValue)) {
			delete(key);
		}
	}

	@Override
	public <T, R> R execute(String key, long expire, T parameter, Function<T, R> function) {
		if(function == null) {
			throw new NullPointerException("function must no be null");
		}
		String value = UUID.randomUUID().toString();
		boolean lockFlag = false;
		R r = null;
		do {
			lockFlag = this.lock(key, value, expire);
			if(lockFlag) {
				r = function.apply(parameter);
				this.unlock(key, value);
			}
		} while (!lockFlag);
		return r;
	}

	@Override
	public <T, R> R tryExecute(String key, long expire, T parameter, Function<T, R> function) {
		if(function == null) {
			throw new NullPointerException("function must no be null");
		}
		String value = UUID.randomUUID().toString();
		R r = null;
		if(this.lock(key, value, expire)) {
			r = function.apply(parameter);
			this.unlock(key, value);
		}
		return r;
	}
}

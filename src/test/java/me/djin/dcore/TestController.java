/**
 * 
 */
package me.djin.dcore;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.alibaba.fastjson.JSON;

import me.djin.dcore.frame.model.IdModel;
import me.djin.dcore.frame.model.Response;
import me.djin.dcore.mq.FutureCallback;
import me.djin.dcore.mq.Message;
import me.djin.dcore.mq.MqAbstractFactory;
import me.djin.dcore.mq.Producer;
import me.djin.dcore.redis.Cacheable;
import me.djin.dcore.redis.RedisLockable;

/**
 * @author djin
 * 测试接口
 */
@RestController
@RequestMapping("/")
public class TestController {
	@Autowired
	private MqAbstractFactory mqFactory;
	@Autowired
	private Cacheable cache;
	@Autowired
	private RedisLockable lockable;
	
	@PostMapping("index")
	public Response<?> index() {
		return Response.ok();
	}
	@PostMapping("params")
	public Response<?> params(@RequestBody Model model) {
		return Response.ok(model);
	}
	@PostMapping("kafka")
	public Response<?> kafka(){
		String message = new Date().toString();
		Producer producer = mqFactory.createProducer();
		producer.send("test", message, new FutureCallback() {
			
			@Override
			public void onSuccess(Message message) {
				System.out.printf("kafka success, %s", message.getMessage());
			}
			
			@Override
			public void onFailure(Message message, Throwable exception) {
				System.out.printf("kafka failure, %s", message.getMessage());
			}
		});
		return Response.ok();
	}
	
	@PostMapping("redis")
	public Response<?> redis(){
		TimeUnit tu = TimeUnit.MINUTES;
		long timeout = 1;
		long ms = System.currentTimeMillis();
		String key = "key"+ms;
		String value = "value"+ms;
		cache.set(key, value, timeout, tu);
		
		String hashKey = "hash"+key;
		HashMap<String, Object> hashmap = new HashMap<>(1);
		hashmap.put(key, value);
		cache.setMap(hashKey, hashmap, timeout, tu);
		
		String objKey = "IdModel:"+key;
		IdModel model = new IdModel();
		model.setId(value);
		cache.setMap(objKey, model, timeout, tu);
		
		String listKey = "list:"+key;
		List<IdModel> list = new ArrayList<>();
		list.add(model);
		list.add(model);
		cache.setList(listKey, list, timeout, tu);
		
		System.out.println("cache output:");
		System.out.println(cache.get(key));
		System.out.println(cache.getMap(hashKey));
		System.out.println(JSON.toJSONString(cache.getObject(objKey, IdModel.class)));
		System.out.println(JSON.toJSONString(cache.getList(listKey, IdModel.class)));
		return Response.ok();
	}
	
	@PostMapping("redisLock")
	public Response<?> redisLock(@RequestBody int expire) throws InterruptedException {
		System.out.println("running in redisLock");
		String key = "LOCK_KEY";
		String value = UUID.randomUUID().toString();
		boolean lockFlag = false;
		do {
			lockFlag = lockable.lock(key, value, expire*2);
			if(lockFlag) {
				System.out.println("current time in redisLock: "+System.currentTimeMillis());
				System.out.println("locked value: " + value);
				Thread.sleep(expire*1000);
				boolean deleteFlag = value.equals(cache.get(key));
				lockable.unlock(key, value);
				System.out.println("unlocked value:" + value+"; state: " + deleteFlag);
			}
		} while (!lockFlag);
		return Response.ok();
	}
	
	@PostMapping("redisLockExecute")
	public Response<?> redisLockExecute(@RequestBody int expire) throws InterruptedException {
		System.out.println("running in redisLock");
		String key = "LOCK_KEY";
		String result = lockable.execute(key, 0, "hello", param->{
			return param+"result";
		});
		System.out.println(result);
		return Response.ok();
	}
	
	@PostMapping("redisUnlock")
	public Response<?> redisUnlock() {
		String key = "LOCK_KEY";
		String value = UUID.randomUUID().toString();
		boolean lockFlag = false;
		do {
			lockFlag = lockable.lock(key, value, 0);
			if(lockFlag) {
				System.out.println("redisUnlock locked");
				lockable.unlock(key, value);
				System.out.println("redisUnlock unlocked");
			}
		} while (!lockFlag);
		return Response.ok();
	}
}

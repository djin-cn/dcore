package me.djin.dcore.mq.thread;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;
import com.google.common.util.concurrent.ThreadFactoryBuilder;

import me.djin.dcore.exception.ApplicationException;
import me.djin.dcore.mq.FutureCallback;
import me.djin.dcore.mq.Consumer;
import me.djin.dcore.mq.Message;
import me.djin.dcore.mq.Message.Status;
import me.djin.dcore.util.PathUtil;

/**
 * 线程消息池，处理多线程消息 通过Kryo序列化为本地文件存储，在数据量不是很大的情况下，性能尚可。
 * 
 * 循环1000条数据，序列化时间不到1秒。数据量越大性能越差，相比kafka、activemq等框架性能下降非常严重。
 * 
 * 适用于要求不是太高的单应用(并发要求不是太高，即时性要求不是太高)。
 * 
 * 当客户端发送多线程消息时，首先将消息池的当前状态序列化，然后再处理消息业务，保证数据的完整性。
 * 
 * 处理完后从消息池中删除消息；当服务重启后，第一次调用时自动从序列化文件加载消息处理。
 * 
 * 消息处理失败时(抛出异常即表示消息处理失败)记录异常状态，每隔一定时间自动重新处理任务，重启后将自动重新处理。
 * 
 * 以下是简单测试(开发环境测试：i7-4790CPU 16内存 3.6GHz 64位 机械硬盘)。
 * 
 * 循环1000条数据，耗时892336455纳秒，约0.89秒,不到1秒；
 * 
 * 循环10000条数据，耗时31898472343纳秒，约32秒；
 * 
 * 循环100000条数据，耗时3906500701594纳秒，约3907秒；
 * 
 * 测试时消息没有删除，一直累加，即十万数据时消息池中存在十万数据，并不符合实际应用场景
 * 
 * @author djin
 *
 */
public class ThreadMessagePool {
	/**
	 * 单例对象
	 */
	private static ThreadMessagePool instance = null;
	/**
	 * 线程消息保存位置
	 */
	private static final String THREAD_MESSAGE_PATH = PathUtil.getJarPath() + "mq.tms";
	/**
	 * 消息池
	 */
	private static final Vector<Message> POOL = new Vector<>();
	/**
	 * 业务处理线程数量
	 */
	private static final int PROCESS_THREAD_COUNT = 100;
	/**
	 * 核心业务处理线程数量
	 */
	private static final int PROCESS_THREAD_CORE_COUNT = 10;
	/**
	 * 线程空闲时间，超过此时间自动销毁，此处设置3s
	 */
	private static final long PROCESS_THREAD_ALIVE_TIME = 3;
	private static final ThreadFactory PROCESS_THREAD_FACTORY = new ThreadFactoryBuilder()
			.setNameFormat("threadMessage-pool-%d").build();
	/**
	 * 业务处理线程
	 */
	private static final ExecutorService PROCESS_THREAD = new ThreadPoolExecutor(PROCESS_THREAD_CORE_COUNT,
			PROCESS_THREAD_COUNT, PROCESS_THREAD_ALIVE_TIME, TimeUnit.SECONDS,
			new ArrayBlockingQueue<>(PROCESS_THREAD_COUNT), PROCESS_THREAD_FACTORY);
	/**
	 * 定时线程，定时循环处理未处理完成的任务
	 */
	private static final ScheduledExecutorService SCHEDULE_THREAD = new ScheduledThreadPoolExecutor(1,
			new BasicThreadFactory.Builder().namingPattern("scheduleMessage-pool-%d").daemon(true).build());
	/**
	 * 处理中的消息队列
	 */
	private static final ConcurrentHashMap<String, Message> PROCESS_QUEUE = new ConcurrentHashMap<>();
	private static final Kryo KRYO = new Kryo();
	private static final Logger LOG = LoggerFactory.getLogger(ThreadMessagePool.class);

	private ThreadMessagePool() {
	}

	/**
	 * 获取初始化实例，第一次获取时自动装载未处理完成的消息
	 * 
	 * @return
	 */
	public static ThreadMessagePool getInstance() {
		if (instance != null) {
			return instance;
		}
		synchronized (THREAD_MESSAGE_PATH) {
			if (instance != null) {
				return instance;
			}
			instance = new ThreadMessagePool();
		}

		Vector<Message> list = instance.deserialize();
		if (list != null && !list.isEmpty()) {
			POOL.addAll(list);
		}
		instance.timer();
		return instance;
	}

	/**
	 * 
	 * 提交并处理消息
	 * 
	 * 此方法包含两个步骤： 1：提交消息，将消息持久化 2：处理消息，通过多线程方式异步处理消息
	 * 
	 * @param topic
	 *            主题
	 * @param message
	 *            要处理的消息
	 * @param callback
	 *            回调函数
	 * @param consumer
	 *            消息消费者
	 */
	public void submit(String topic, String message, FutureCallback callback, Consumer consumer) {
		Message mes = new Message();
		mes.setTopic(topic);
		mes.setMessage(message);
		mes.setStatus(Status.PENDING);
		mes.setCallback(callback);
		mes.setHandler(consumer);
		POOL.add(mes);
		serialize();
		process(mes);
	}

	/**
	 * 消息处理。此方法不会将消息持久化，只是处理消息，有可能会数据丢失(如：意外中断等)
	 * 
	 * @param message
	 */
	public void process(Message message) {
		String key = message.getTopic() + message.getMessage();
		boolean flagQueue = addToQueue(key, message);
		if (flagQueue) {
			boolean flagDispatch = dispatch(message);
			if (flagDispatch) {
				return;
			}
			PROCESS_QUEUE.remove(key);
		}
	}

	/**
	 * 获取消息池的消息，消息按照顺序排序，优先未处理消息，其次处理失败消息，最后已处理的消息
	 * 
	 * @return
	 */
	public List<Message> getMessageList() {
		@SuppressWarnings("unchecked")
		Vector<Message> list = (Vector<Message>) POOL.clone();
		// 对数组排序，返回值大于等于1时，item2排于item1之前，当返回值小于1时，item1排于item2之前
		list.sort((item1, item2) -> {
			/**
			 * 优先未处理的任务
			 */
			if (item1.getStatus() == Status.PENDING) {
				return 0;
			}
			if (item2.getStatus() == Status.PENDING) {
				return 1;
			}
			/**
			 * 其次处理失败的任务，失败时间越早则优先级越高
			 */
			if (item1.getStatus() == Status.FAILURE) {
				if (item2.getStatus() != Status.FAILURE) {
					return 0;
				}
				return item1.getLatestTime().compareTo(item2.getLatestTime());
			}
			if (item2.getStatus() == Status.FAILURE) {
				return 1;
			}
			return 0;
		});
		return list;
	}

	/**
	 * 删除消息
	 * 
	 * @param topic
	 *            主题
	 * @param message
	 *            要处理的消息
	 */
	public void delete(String topic, String message) {
		POOL.removeIf(item -> item == null || (item.getTopic() == topic && item.getMessage() == message));
		serialize();
	}

	public static void main(String[] args) {
		long start = System.nanoTime();
		int loop = 1000000;
		System.out.println(start);
		for (int i = 0; i < loop; i++) {
			ThreadMessagePool.getInstance().submit("demo" + i, "用户注册。注册账号:account;注册邮箱:admin@email.com" + i,
					new FutureCallback() {
						@Override
						public void onSuccess(Message message) {
							LOG.debug("onSuccess: " + message.toString());
						}

						@Override
						public void onFailure(Message message, Throwable exception) {
							LOG.debug("onFailure: " + message.toString());
						}
					}, new DemoConsumer());
		}
		long end = System.nanoTime();
		System.out.println("耗时:"+(end - start));
	}

	/**
	 * 定時器，每隔5秒执行清理一次任务
	 */
	private void timer() {
		long delay = 1000;
		long period = 5000;
		SCHEDULE_THREAD.scheduleAtFixedRate(() -> {
			try {
			List<Message> list = getMessageList();
			LOG.trace("定时处理线程消息，处理时间："+System.nanoTime()+"，消息总数：" + list.size());
			Iterator<Message> iterator = list.iterator();
			while (iterator.hasNext()) {
				Message message = iterator.next();
				instance.process(message);
			}
			}catch (Exception e) {
				LOG.error(e.getMessage(), e);
			}
		}, delay, period, TimeUnit.MILLISECONDS);
	}

	/**
	 * 多线程将消息分发给对应的消息消费者进行处理
	 * 
	 * @param message
	 */
	private boolean dispatch(Message message) {
		try {
			PROCESS_THREAD.execute(() -> {
				LOG.debug("thread message process: " + message.toString());
				try {
					message.getHandler().process(message.getMessage());
					message.setStatus(Status.SUCCESS);
					delete(message.getTopic(), message.getMessage());
					LOG.debug("thread message processed success: " + message.toString());
					message.getCallback().onSuccess(message);
				} catch (Exception e) {
					message.setStatus(Status.FAILURE);
					message.setLatestTime(new Date());
					LOG.error("thread message error: {}; {}", message, e);
					message.getCallback().onFailure(message, e);
				} finally {
					// 无论处理成功或者处理失败，都需要将消息从待处理消息队列中移除，因为如果处理失败，会定时重新处理，直到处理成功
					PROCESS_QUEUE.remove(message.getTopic() + message.getMessage());
				}

			});
			return true;
		} catch (RejectedExecutionException e) {
			return false;
		}
	}

	/**
	 * 将消息添加到待处理消息队列，已成功处理的消息不会添加
	 * 
	 * @param key
	 * @param message
	 * @return
	 */
	private boolean addToQueue(String key, Message message) {
		if (message.getStatus() == Status.SUCCESS || PROCESS_QUEUE.containsKey(key)) {
			return false;
		}
		synchronized (LOG) {
			if (message.getStatus() == Status.SUCCESS || PROCESS_QUEUE.containsKey(key)) {
				return false;
			}
			PROCESS_QUEUE.put(key, message);
		}
		return true;
	}

	/**
	 * 反序列化线程消息
	 * 
	 * @return
	 */
	private Vector<Message> deserialize() {
		if (!PathUtil.existPath(THREAD_MESSAGE_PATH)) {
			return null;
		}
		try {
			Input input = new Input(new FileInputStream(THREAD_MESSAGE_PATH));
			@SuppressWarnings("unchecked")
			Vector<Message> list = (Vector<Message>) KRYO.readClassAndObject(input);
			return list;
		} catch (FileNotFoundException | com.esotericsoftware.kryo.KryoException e) {
			LOG.error(e.getMessage(), e);
			return null;
		}
	}

	/**
	 * 序列化线程消息
	 */
	private synchronized void serialize() {
		if (!PathUtil.initPath(THREAD_MESSAGE_PATH)) {
			throw new ApplicationException(new FileNotFoundException(THREAD_MESSAGE_PATH), null);
		}
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(THREAD_MESSAGE_PATH);
		} catch (FileNotFoundException e) {
			throw new ApplicationException(e, null);
		}
		Output output = new Output(fos);
		try {
			KRYO.writeClassAndObject(output, POOL.clone());
		}catch (Exception e) {
			LOG.error(e.getMessage(), e);
		}
		output.close();
	}
}
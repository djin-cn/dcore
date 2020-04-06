package me.djin.dcore.mq;

import java.util.Date;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.annotation.JSONField;

/**
 * 线程消息
 * 
 * @author djin
 *
 */
public class Message {
	/**
	 * 消息状态
	 * @author djin
	 *
	 */
	public enum Status{
		/**
		 * 待处理
		 */
		PENDING,
		/**
		 * 处理成功
		 */
		SUCCESS,
		/**
		 * 处理失败
		 */
		FAILURE
	}
	/**
	 * 主题
	 */
	@JSONField(ordinal = 1)
	private String topic;
	/**
	 * 消息状态
	 */
	@JSONField(ordinal = 2)
	private Status status;
	/**
	 * 最后处理时间
	 */
	@JSONField(ordinal = 3)
	private Date latestTime;
	/**
	 * 消息
	 */
	@JSONField(ordinal = 4)
	private String message;
	/**
	 * 消息处理器
	 */
	@JSONField(ordinal = 5)
	private Consumer handler;
	/**
	 * 
	 */
	@JSONField(ordinal = 6)
	private FutureCallback callback;

	public String getTopic() {
		return topic;
	}

	public void setTopic(String topic) {
		this.topic = topic;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public Status getStatus() {
		return status;
	}

	public void setStatus(Status status) {
		this.status = status;
	}

	public Date getLatestTime() {
		return latestTime;
	}

	public void setLatestTime(Date latestTime) {
		this.latestTime = latestTime;
	}

	public Consumer getHandler() {
		return handler;
	}

	public void setHandler(Consumer handler) {
		this.handler = handler;
	}

	public FutureCallback getCallback() {
		return callback;
	}

	public void setCallback(FutureCallback callback) {
		this.callback = callback;
	}

	@Override
	public String toString() {
		return JSON.toJSONString(this);
	}
}
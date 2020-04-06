package me.djin.dcore.mq;

/**
 * @author djin
 * 消息生产者
 */
public interface Producer {
	/**
	 * 发送主题消息
	 * @param topic 主题
	 * @param message 消息, 一般是JSON格式的消息对象
	 */
	void send(String topic, String message);
	
	/**
	 * 发送主题消息
	 * @param topic 主题
	 * @param message 消息, 一般是JSON格式的消息对象
	 * @param callback 消息处理成功或者失败的回调函数
	 */
	void send(String topic, String message, FutureCallback callback);
}
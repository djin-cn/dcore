package me.djin.dcore.mq;

/**
 * 消息处理回调接口
 * @author djin
 *
 */
public interface FutureCallback {
	/**
	 * 消息处理成功的回调函数
	 * @param message
	 */
	void onSuccess(Message message);
	/**
	 * 消息处理失败的回调函数
	 * @param message
	 * @param exception
	 */
	void onFailure(Message message, Throwable exception);
}

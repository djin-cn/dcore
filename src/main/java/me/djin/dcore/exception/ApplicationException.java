package me.djin.dcore.exception;

import java.io.Serializable;

import me.djin.dcore.message.MessageHelper;

/**
 * 系统异常类。
 * <br />此异常类要求记录在出现异常时的数据状态，便于随时排查
 * <br />一般情况下系统抛出异常时只能抛出此异常
 * @author djin
 *
 */
@SuppressWarnings("serial")
public class ApplicationException extends RuntimeException implements Serializable  {
	private int code = 0;
	private Object data = null;

	/**
	 * 系统异常
	 * @param code 错误码，可在error_message.properties文件定义
	 * @param data 引发异常的数据，异常时的数据状态
	 * @param params 异常消息需要用到的参数
	 */
	public ApplicationException(int code, Object data, Object... params) {
		this(code, data, null, params);
	}

	/**
	 * 系统异常
	 * @param e 异常
	 * @param data 引发异常的数据，异常时的数据状态
	 */
	public ApplicationException(Exception e, Object data) {
		this(0, data, e);
	}

	/**
	 * 系统异常
	 * @param code 错误码，可在error_message.properties文件定义
	 * @param data 引发异常的数据，异常时的数据状态
	 * @param e 异常
	 * @param params 异常消息需要用到的参数
	 */
	public ApplicationException(int code, Object data, Exception e, Object... params) {
		super(MessageHelper.getMessage(String.valueOf(code), params), e);
		this.data = data;
		this.code = code;
	}

	/**
	 * 获取异常数据
	 * @return
	 */
	public Object getData() {
		return data;
	}
	
	/**
	 * 获取错误码
	 * @return
	 */
	public int getCode() {
		return code;
	}
}
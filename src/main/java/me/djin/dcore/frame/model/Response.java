package me.djin.dcore.frame.model;

import java.io.Serializable;

import com.alibaba.fastjson.JSON;

import io.swagger.annotations.ApiModel;
import me.djin.dcore.message.MessageHelper;

/**
 * 同一输出格式包
 * @author djin
 *
 */
@ApiModel("Output")
@SuppressWarnings("serial")
public class Response<T> implements Serializable {
	private String status="1";
	private T data = null;
	private String statusText = null;
	
	/**
	 * 默认正确输出
	 */
	public Response() {
		this("1");
	}
	
	/**
	 * 统一输出格式
	 * @param status 状态码，错误码
	 */
	public Response(String status) {
		setStatus(status);
		setStatusText(status);
	}
	
	/**
	 * 统一输出格式
	 * @param status 状态码，错误码
	 * @param data 输出数据
	 */
	public Response(String status, T data) {
		setStatus(status);
		setData(data);
		setStatusText(status);
	}
	
	/**
	 * 统一输出格式
	 * @param status 状态码，错误码
	 * @param params 状态码对应消息的参数
	 */
	public Response(String status, Object[] params) {
		setStatus(status);
		setStatusText(status, params);
	}
	
	/**
	 * 统一输出格式
	 * @param status 状态码，错误码
	 * @param data 输出数据
	 * @param params 状态码对应消息的参数
	 */
	public Response(String status, T data, Object[] params) {
		setStatus(status);
		setData(data);
		setStatusText(status, params);
	}
	
	/**
	 * 统一输出格式
	 * @param status 状态码，错误码
	 */
	public Response(int status) {
		setStatus(String.valueOf(status));
		setStatusText(String.valueOf(status));
	}
	
	/**
	 * 统一输出格式
	 * @param status 状态码，错误码
	 * @param data 输出数据
	 */
	public Response(int status, T data) {
		setStatus(String.valueOf(status));
		setData(data);
		setStatusText(String.valueOf(status));
	}
	
	/**
	 * 统一输出格式
	 * @param status 状态码，错误码
	 * @param params 状态码对应消息的参数
	 */
	public Response(int status, Object[] params) {
		setStatus(String.valueOf(status));
		setStatusText(String.valueOf(status), params);
	}
	
	/**
	 * 统一输出格式
	 * @param status 状态码，错误码
	 * @param data 输出数据
	 * @param params 状态码对应消息的参数
	 */
	public Response(int status, T data, Object[] params) {
		setStatus(String.valueOf(status));
		setData(data);
		setStatusText(String.valueOf(status), params);
	}
	
	/**
	 * 获取状态码，错误码
	 * @return
	 */
	public String getStatus() {
		return status;
	}

	/**
	 * 设置状态码，错误码
	 * @param status
	 */
	public void setStatus(String status) {
		this.status = status;
	}

	/**
	 * 获取状态消息
	 * @return
	 */
	public String getStatusText() {
		return statusText;
	}
	
	/**
	 * 设置状态消息
	 * @param status 错误码
	 * @param params 错误消息参数
	 */
	private void setStatusText(String status, Object... params) {
		statusText = MessageHelper.getMessage(getStatus(), params);
	}
	
	/**
	 * 获取输出数据
	 * @return
	 */
	public T getData() {
		return data;
	}
	
	/**
	 * 设置输出数据
	 * @param data
	 */
	public void setData(T data) {
		this.data = data;
	}
	
	@Override
	public String toString() {
		return JSON.toJSONString(this);
	}
	
	/**
	 * 输出成功消息
	 * @return
	 */
	public static <T> Response<T> ok() {
		return new Response<T>(1);
	}
	
	/**
	 * 输出成功消息并返回结果
	 * @return
	 */
	public static <T> Response<T> ok(T t) {
		return new Response<>(1, t);
	}
	
	/**
	 * 输出错误消息
	 * @return
	 */
	public static <T> Response<T> error(){
		return new Response<T>(0);
	}
	
	/**
	 * 输出错误信息
	 * @param code 错误码
	 * @return
	 */
	public static <T> Response<T> error(int code){
		return new Response<T>(code);
	}
}
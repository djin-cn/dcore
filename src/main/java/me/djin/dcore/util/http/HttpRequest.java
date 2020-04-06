package me.djin.dcore.util.http;

import java.io.IOException;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Request.Builder;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * okhttp3.Request的包装类
 * @author djin
 *
 */
public class HttpRequest {
	private static final OkHttpClient CLIENT = new OkHttpClient();
	private Builder builder = null;
	
	/**
	 * GET请求
	 * @param url
	 * @return
	 */
	public HttpRequest get(String url) {
		builder = new Request.Builder().url(url);
		return this;
	}
	
	/**
	 * POST请求
	 * @param url
	 * @param body
	 * @return
	 */
	public HttpRequest post(String url, RequestBody body) {
		builder = new Request.Builder().url(url).post(body);
		return this;
	}
	
	/**
	 * DELETE请求
	 * @param url
	 * @param body
	 * @return
	 */
	public HttpRequest delete(String url, RequestBody body) {
		builder = new Request.Builder().url(url).delete(body);
		return this;
	}
	
	/**
	 * PUT请求
	 * @param url
	 * @param body
	 * @return
	 */
	public HttpRequest put(String url, RequestBody body) {
		builder = new Request.Builder().url(url).put(body);
		return this;
	}
	
	/**
	 * 设置请求头
	 * @param name
	 * @param value
	 * @return
	 */
	public HttpRequest setHeaders(String name, String value) {
		builder.addHeader(name, value);
		return this;
	}
	
	/**
	 * 执行请求
	 * @return
	 * @throws IOException
	 */
	public HttpResponse execute() throws IOException {
		Request request = builder.build();
		Response response = CLIENT.newCall(request).execute();
		return new HttpResponse(response);
	}
}
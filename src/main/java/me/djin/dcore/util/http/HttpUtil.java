package me.djin.dcore.util.http;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.alibaba.fastjson.JSON;

import me.djin.dcore.util.MimeTypeUtils;
import okhttp3.FormBody;
import okhttp3.FormBody.Builder;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.RequestBody;

/**
 * @author djin
 *         <pre>
 * 本工具基于okhttp 3.11.0封装，主要简化调用过程。
 * 使用方式示例：
 * HttpUtil.get("https://www.baidu.com/").execute().getString();
 * HttpUtil.get("https://www.baidu.com/").execute().getJson();
 * HttpUtil.get("https://www.baidu.com/").execute().getFile();
 *         </pre>
 * 
 *         <pre>
 * http请求服务。
 * 单线程串行10000次纯html请求测试：
 * 内网请求每秒钟大概请求数900个，即每个请求大概1.1毫秒。
 * 外网请求(https://www.baidu.com/)每秒钟大概请求数85个，即每个请求大概11.8毫秒。
 * 外网请求(http://www.ifeng.com/)每秒钟大概请求数28个，即每个请求大概35.7毫秒。
 * 本测试对服务器性能没有参考价值：
 * 第一：单线程串行方式请求并不能反映出服务器性能；
 * 第二：请求受网络状态、服务器配置等影响较大；
 *         </pre>
 */
public class HttpUtil {
	/**
	 * 根据参数构造请求体
	 * 
	 * @param params
	 *            请求参数，如果是上传文件，则值必须为File类型
	 * @return
	 */
	private static RequestBody buildRequestBody(Map<String, Object> params) {
		RequestBody requestBody = null;
		// 是否Multipart，用于判断是否文件上传
		boolean isMultipart = false;
		for (Map.Entry<String, Object> entry : params.entrySet()) {
			// 如果请求参数包含File,表示文件上传
			if (entry.getValue() instanceof File) {
				isMultipart = true;
				break;
			}
		}

		// 普通表单提交
		if (!isMultipart) {
			Builder builder = new FormBody.Builder();
			for (Map.Entry<String, Object> entry : params.entrySet()) {
				builder.add(entry.getKey(), entry.getValue().toString());
			}
			requestBody = builder.build();
		} else {// 有文件上传
			okhttp3.MultipartBody.Builder builder = new MultipartBody.Builder().setType(MultipartBody.FORM);
			for (Map.Entry<String, Object> entry : params.entrySet()) {

				// 文件上传
				if (entry.getValue() instanceof File) {
					File file = (File) entry.getValue();
					MediaType mediaType = MediaType.parse(MimeTypeUtils.parse(file.getName()).toString());
					builder.addFormDataPart(entry.getKey(), file.getName(), RequestBody.create(mediaType, file));
				} else {// 表单提交
					builder.addFormDataPart(entry.getKey(), entry.getValue().toString());
				}
			}
			requestBody = builder.build();
		}
		return requestBody;
	}

	/**
	 * GET请求
	 * 
	 * @param url
	 *            请求地址
	 * @return
	 * @throws IOException
	 */
	public static HttpRequest get(String url) throws IOException {
		HttpRequest request = new HttpRequest();
		request.get(url);
		return request;
	}

	/**
	 * POST请求
	 * 
	 * @param url
	 *            请求地址
	 * @return
	 */
	public static HttpRequest post(String url) {
		return post(url, "");
	}

	/**
	 * POST请求
	 * 
	 * @param url
	 * @param content
	 * @return
	 */
	public static HttpRequest post(String url, String content) {
		HttpRequest request = new HttpRequest();
		if (content == null) {
			content = "";
		}
		MediaType mediaType = MediaType.parse(MimeTypeUtils.Type.TEXT_PLAIN.toString());
		RequestBody body = RequestBody.create(mediaType, content);
		request.post(url, body);
		return request;
	}

	/**
	 * POST请求，支持文件上传
	 * 
	 * @param url
	 * @param params
	 *            请求参数，如果是上传文件，则值必须为File类型
	 * @return
	 */
	public static HttpRequest post(String url, Map<String, Object> params) {
		if (params == null || params.isEmpty()) {
			return post(url);
		}
		HttpRequest request = new HttpRequest();
		RequestBody requestBody = buildRequestBody(params);
		request.post(url, requestBody);
		return request;
	}

	/**
	 * 上传单文件
	 * 
	 * @param url
	 * @param filePath
	 *            文件路径
	 * @param formName
	 *            表单名称
	 * @return
	 */
	public static HttpRequest postFile(String url, String filePath, String formName) {
		HashMap<String, Object> map = new HashMap<String, Object>(1);
		map.put(formName, new File(filePath));
		return post(url, map);
	}

	/**
	 * PUT请求
	 * 
	 * @param url
	 *            请求地址
	 * @return
	 */
	public static HttpRequest put(String url) {
		HttpRequest request = new HttpRequest();
		MediaType mediaType = MediaType.parse(MimeTypeUtils.Type.TEXT_PLAIN.toString());
		RequestBody body = RequestBody.create(mediaType, "");
		request.put(url, body);
		return request;
	}

	/**
	 * PUT请求，支持文件上传
	 * 
	 * @param url
	 * @param params
	 *            请求参数，如果是上传文件，则值必须为File类型
	 * @return
	 */
	public static HttpRequest put(String url, Map<String, Object> params) {
		if (params == null || params.isEmpty()) {
			return put(url);
		}
		HttpRequest request = new HttpRequest();
		RequestBody requestBody = buildRequestBody(params);
		request.put(url, requestBody);
		return request;
	}

	/**
	 * DELETE请求
	 * 
	 * @param url
	 *            请求地址
	 * @return
	 */
	public static HttpRequest delete(String url) {
		HttpRequest request = new HttpRequest();
		MediaType mediaType = MediaType.parse(MimeTypeUtils.Type.TEXT_PLAIN.toString());
		RequestBody body = RequestBody.create(mediaType, "");
		request.delete(url, body);
		return request;
	}

	/**
	 * DELETE请求，支持文件上传
	 * 
	 * @param url
	 * @param params
	 *            请求参数，如果是上传文件，则值必须为File类型
	 * @return
	 */
	public static HttpRequest delete(String url, Map<String, Object> params) {
		if (params == null || params.isEmpty()) {
			return delete(url);
		}
		HttpRequest request = new HttpRequest();
		RequestBody requestBody = buildRequestBody(params);
		request.delete(url, requestBody);
		return request;
	}

	/**
	 * POST请求，Content-Type=application/json
	 * 
	 * @param url
	 * @param content
	 * @return
	 */
	public static HttpRequest postJson(String url) {
		return postJson(url, "");
	}

	/**
	 * POST请求，Content-Type=application/json
	 * 
	 * @param url
	 * @param content
	 * @return
	 */
	public static HttpRequest postJson(String url, String content) {
		HttpRequest request = new HttpRequest();
		if (content == null) {
			content = "";
		}
		MediaType mediaType = MediaType.parse(MimeTypeUtils.Type.APPLICATION_JSON.toString());
		RequestBody body = RequestBody.create(mediaType, content);
		request.post(url, body);
		return request;
	}

	/**
	 * POST请求,不支持文件上传。Content-Type=application/json
	 * 
	 * @param url
	 * @param params
	 * @return
	 */
	public static HttpRequest postJson(String url, Map<String, Object> params) {
		if (params == null || params.isEmpty()) {
			return postJson(url);
		}
		String content = JSON.toJSONString(params);
		return postJson(url, content);
	}
}
/**
 * 
 */
package me.djin.dcore.frame.common;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.alibaba.fastjson.JSONObject;

import me.djin.dcore.frame.model.CurrentUser;

/**
 * 全局请求参数类
 * 
 * 可获取pn、pc参数
 * 
 * 此类的参数获取只能是在web请求环境下，其它环境不适用，如：多线程、定时任务等
 * 
 * @author djin
 */
public class RequestParams {
	/**
	 * 获取当前请求
	 * 
	 * @return
	 */
	private static final HttpServletRequest currentRequest() {
		String exceptionMessage = "RequestParams使用错误，RequestParams只能获取web请求参数，不能用于其它时间和场景(如：多线程、定时任务等)";
		ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		if (attrs == null) {
			throw new RuntimeException(exceptionMessage);
		}
		HttpServletRequest request = attrs.getRequest();
		if (request == null) {
			throw new RuntimeException(exceptionMessage);
		}
		return request;
	}

	/**
	 * 获取当前页码，永远返回数字，如果参数小于1或者为非字符串或者为NULL则返回1
	 * 
	 * 通过请求参数pn设置
	 * 
	 * @return
	 */
	public static final int getPageNumber() {
		String strPn = currentRequest().getParameter("pn");
		int pn = 0;
		try {
			pn = Integer.parseInt(strPn);
		} catch (NumberFormatException e) {
			pn = 1;
		}
		if (pn < 1) {
			pn = 1;
		}
		return pn;
	}

	/**
	 * 获取当前每页显示数量，永远返回数字，如果参数小于1或者为非字符串或者为NULL则返回10
	 * 
	 * 通过请求参数pc设置
	 * 
	 * @return
	 */
	public static final int getPageCount() {
		String strPc = currentRequest().getParameter("pc");
		int pc = 0;
		try {
			pc = Integer.parseInt(strPc);
		} catch (NumberFormatException e) {
			pc = 10;
		}
		if (pc < 1) {
			pc = 10;
		}
		return pc;
	}

	/**
	 * 获取当前登录用户
	 * 
	 * 如果没有当前用户则返回空实例用户对象，可根据userid判断是否存在当前用户
	 * 
	 * @return
	 */
	public static final CurrentUser getCurrentUser() {
		HttpServletRequest request = currentRequest();
		CurrentUser user = (CurrentUser) request.getAttribute(CurrentUser.TOKEN_HEADER);
		if (user != null && user.getUserid() != null) {
			return user;
		}
		String token = request.getHeader(CurrentUser.TOKEN_HEADER);
		if(token == null) {
			token = "";
		}
		try {
			token = URLDecoder.decode(token, StandardCharsets.UTF_8.name());
		} catch (UnsupportedEncodingException e1) {
			token = null;
		} catch (Exception e) {
			if (token == null) {
				token = "";
			}
			throw new RuntimeException("解码当前用户错误, 用户令牌: " + token, e);
		}
		if (StringUtils.isBlank(token)) {
			user = new CurrentUser();
		} else {
			try {
				user = JSONObject.parseObject(token, CurrentUser.class);
			} catch (Exception e) {
				user = new CurrentUser();
			}
		}
		request.setAttribute(CurrentUser.TOKEN_HEADER, user);
		return user;
	}
	
	/**
	 * 获取客户端IP,可以获取代理后的IP
	 * 
	 * 一般nginx配置习惯,代理链放到X-Forwarded-For
	 * 
	 * 所以此方法优先获取X-Forwarded-For，然后获取request.getRemoteAddr();
	 * 
	 * 本方法不会从X-Real-IP获取IP地址，虽然可能有效
	 */
	public static final String getRemoteAddr() {
		String unknown = "unknown";
		HttpServletRequest request = currentRequest();
		String ip = request.getHeader("X-Forwarded-For");
		if(StringUtils.isNotBlank(ip) && !unknown.equalsIgnoreCase(ip)) {
			String[] ips = ip.split(",");
			for (String tmp : ips) {
				if(unknown.equalsIgnoreCase(tmp)) {
					continue;
				}
				ip = tmp;
				return ip;
			}
		}
		return request.getRemoteAddr();
	}
}

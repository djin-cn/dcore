/**
 * 
 */
package me.djin.dcore.message;

import java.io.UnsupportedEncodingException;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.PropertyResourceBundle;
import java.util.ResourceBundle;

import me.djin.dcore.exception.ApplicationException;

/**
 * @author djin 
 * 消息帮助类，用于获取预定义消息及消息国际化<br />
 * 消息文件必须位于{classpath}/i18n目录之下，且文件名必须已message开头，message之后添加语言区域，eg:<br />
 * message_zh_CN.properties; message_en_US.properties<br />
 * 如果没有找到对应区域语言的文件，则使用默认文件message.properties,所以默认message.properties必不可少<br />
 * 注意：所有的语言包文件必须为UTF-8无BOM编码，否则会乱码
 */
public class MessageHelper {
	private static final HashMap<String, ResourceBundle> RESOURCES = new HashMap<String, ResourceBundle>();
	private static final String BASE_NAME = "i18n/message";
	
	/**
	 * 加载语言区域的语言包
	 * @param locale 语言区域
	 * @return
	 */
	private static ResourceBundle loadLocaleResource(Locale locale) {
		if(locale == null) {
			locale = Locale.getDefault();
		}
		String language = locale.getLanguage();
		if(RESOURCES.containsKey(language)) {
			return RESOURCES.get(language);
		}
		ResourceBundle resource = null;
		try {
			resource = PropertyResourceBundle.getBundle(BASE_NAME, locale);
		}catch (MissingResourceException e) {
			throw e;
		}
		RESOURCES.put(language, resource);
		return resource;
	}

	/**
	 * 获取消息
	 * @param code 消息的键
	 * @return
	 */
	public static String getMessage(String code) {
		return getMessage(code, null);
	}

	/**
	 * 获取消息
	 * @param code 消息的键
	 * @param params 消息需要的参数
	 * @return
	 */
	public static String getMessage(String code, Object... params) {
		return getMessage(code, null, params);
	}
	
	/**
	 * 获取消息
	 * @param code 消息的键
	 * @param locale 语言区域
	 * @param params 消息需要的参数
	 * @return
	 */
	public static String getMessage(String code, Locale locale, Object... params) {
		ResourceBundle resource = loadLocaleResource(locale);
		String message = resource.getString(code);
		String messageUtf8;
		try {
			messageUtf8 = new String(message.getBytes("ISO-8859-1"), "UTF-8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			throw new ApplicationException(e, message);
		}
		return MessageFormat.format(messageUtf8, params);
	}
}

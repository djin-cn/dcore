package me.djin.dcore.util;

import java.util.Properties;

import com.google.code.kaptcha.Constants;
import com.google.code.kaptcha.Producer;
import com.google.code.kaptcha.util.Config;

/**
 * 验证码生成工具，基于google的kaptcha
 * @author djin
 *
 */
public class CaptchaUtils {
	private static Producer producer = null;
	
	/**
	 * 使用默认配置初始化，无论初始化多少次，只有第一次有效<br/>
	 * 默认宽高比为4:1,默认宽度200,高度50，一般验证码设计时可基于4:1的比例设置图片<br/>
	 * 限制了验证码的字符内容，人眼不方便识别的字符不会生成，比如0-O,1-I,2-Z,5-S等等
	 */
	public static void init() {
		if(producer != null) {
			return;
		}
		Properties props = new Properties();
		props.put(Constants.KAPTCHA_BORDER, "no");
		props.put(Constants.KAPTCHA_BORDER_COLOR, "105,179,90");
		props.put(Constants.KAPTCHA_IMAGE_WIDTH, "200");
		props.put(Constants.KAPTCHA_IMAGE_HEIGHT, "50");
		props.put(Constants.KAPTCHA_TEXTPRODUCER_FONT_SIZE, "45");
		props.put(Constants.KAPTCHA_SESSION_KEY, "code");
		props.put(Constants.KAPTCHA_TEXTPRODUCER_CHAR_LENGTH, "4");
		props.put(Constants.KAPTCHA_TEXTPRODUCER_FONT_NAMES, "宋体,楷体,微软雅黑");
		props.put(Constants.KAPTCHA_TEXTPRODUCER_CHAR_STRING, "ACEFHKMNPRTUWX3467");
		init(props);
	}
	
	/**
	 * 使用自定义配置初始化，无论初始化多少次，只有第一次有效
	 * @param props
	 */
	public static void init(Properties props) {
		if(producer != null) {
			return;
		}
		Config config = new Config(props);
		producer = config.getProducerImpl();
	}
	
	/**
	 * 获取验证码生成实例，可通过以下方式生成验证码.
	 * <pre>
	 *     //关闭基于磁盘的缓存，不建议省略这一步，否则在某些情况下会报错，且可以免除创建和销毁文件带来的开销，对小图片生成比较有利
	 *     ImageIO.setUseCache(false);
	 *     //设置过期时间
	 *     response.setDateHeader("Expires", 0);
	 *     //设置HTTP/1.1不缓存
	 *     response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
	 *     response.addHeader("Cache-Control", "post-check=0, pre-check=0");
	 *     //设置HTTP/1.0不缓存
	 *     response.setHeader("Pragma", "no-cache");
	 *     //设置图片格式为jpeg
	 *     response.setContentType("image/jpeg");
	 *     //生成验证码
	 *     String captchText = CaptchaUtils.getInstance().createText();
	 *     //可在此处将验证码保存到Session或者Cookie。如果放Cookie需要将验证码加密，否则没有意义。此处没有加密并设置过期时间5分钟
	 *     Cookie cookie = new Cookie("KAPTCHA_COOKIE_KEY", captchText);
	 *     cookie.setMaxAge(60*5);
	 *     cookie.setPath("/");
	 *     response.addCookie(cookie);
	 *     //将验证码生成为图片
	 *     BufferedImage image = CaptchaUtils.getInstance().createImage(captchText);
	 *     //输出图片，此步骤一般放最后
	 *     ImageIO.write(image, "jpg", response.getOutputStream());
	 * </pre>
	 * @return
	 */
	public static Producer getInstance() {
		if(producer == null) {
			init();
		}
		return producer;
	}
}

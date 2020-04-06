/**
 * 
 */
package me.djin.dcore.aspect;

import java.util.UUID;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.Signature;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializeConfig;

/**
 * @author djin 请求切面 Aspect执行顺序分两种情况：正常情况和异常情况。
 * 
 *         正常情况执行顺序：around-before-调用实际方法-around-after-afterReturning
 * 
 *         异常情况执行顺序：around-before-调用实际方法-after-afterThrowing
 * 
 *         异常情况默认是不会再执行around调用实际方法之后的代码的，除非进行异常捕获。
 * 
 *         如果around异常捕获后需要继续抛出异常，如果不抛出会将异常抛弃导致其它地方无法正常处理异常。
 */
@Aspect
public class RequestAspect {
	private static final Logger LOGGER = LoggerFactory.getLogger(RequestAspect.class);
	/**
	 * FastJson序列化配置
	 */
	private static final SerializeConfig JSON_CONFIG = new SerializeConfig();
	/**
	 * 1: SpeedEnum 2: 完整方法名(包含类名) 3: 毫秒数
	 */
	private static final String SPEED_LOG_EXPRESS = "SPEED:{}, {} {}ms";
	/**
	 * 1: 请求状态，RequestEnum 2: 异常消息 3: 完整方法名(包含类名) 4: JSON格式的参数
	 */
	private static final String INFO_LOG_EXPRESS = "%s:%s %s(%s)";
	/**
	 * 毫秒换算到纳秒，1毫秒=100万纳秒
	 */
	private static final long MS_TO_NANO = 1000000L;

	/**
	 * 切入点表达式, 切入所有的请求入口
	 */
	private static final String POINTCUT_EXPRESS = "@annotation(org.springframework.web.bind.annotation.RequestMapping)"
			+ "|| @annotation(org.springframework.web.bind.annotation.PostMapping)"
			+ "|| @annotation(org.springframework.web.bind.annotation.GetMapping)"
			+ "|| @annotation(org.springframework.web.bind.annotation.DeleteMapping)"
			+ "|| @annotation(org.springframework.web.bind.annotation.PutMapping)"
			+ "|| @annotation(org.springframework.web.bind.annotation.PatchMapping)";

	/**
	 * 切入点
	 */
	@Pointcut(POINTCUT_EXPRESS)
	public void requestLog() {
	}

	@Around("requestLog()")
	public Object doAround(ProceedingJoinPoint proceedingJoinPoint) throws Throwable {
		System.out.println("doAround");
		MDC.put("THREAD_ID", UUID.randomUUID().toString());
		// 定义1秒之内完成为正常
		int normalSpeed = 1000;
		long requestStartTime = System.nanoTime();
		try {
			return proceedingJoinPoint.proceed();
		} catch (Throwable e) {
			throw e;
		} finally {
			long requestEndTime = System.nanoTime();
			long interval = (requestEndTime - requestStartTime) / MS_TO_NANO;
			SpeedEnum speedEnum = interval > normalSpeed ? SpeedEnum.TIMEOUT : SpeedEnum.NORMAL;
			LOGGER.info(SPEED_LOG_EXPRESS, speedEnum.name(), getInvokeMethodName(proceedingJoinPoint), interval);
		}
	}

	/**
	 * 记录错误日志
	 * 
	 * @param joinPoint
	 * @param e
	 */
	@AfterThrowing(pointcut = "requestLog()", throwing = "e")
	public void doAfterThrowing(JoinPoint joinPoint, Throwable e) {
		System.out.println("doAfterThrowing");
		String message = String.format(INFO_LOG_EXPRESS, RequestEnum.REQUEST_ERROR, e.getMessage(),
				getInvokeMethodName(joinPoint), getInvokeParams(joinPoint));
		LOGGER.error(message, e);
	}

	/**
	 * 记录正常日志
	 * 
	 * @param joinPoint
	 */
	@AfterReturning("requestLog()")
	public void doAfterReturning(JoinPoint joinPoint) {
		System.out.println("doAfterReturning");
		String message = String.format(INFO_LOG_EXPRESS, RequestEnum.REQUEST_SUCCESS, "",
				getInvokeMethodName(joinPoint), getInvokeParams(joinPoint));
		LOGGER.info(message);
	}

	/**
	 * 获取调用方法的参数
	 * 
	 * @param joinPoint
	 * @return
	 */
	private String getInvokeParams(JoinPoint joinPoint) {
		Object[] args = joinPoint.getArgs();
		if (args != null && args.length > 0) {
			StringBuffer sb = new StringBuffer();
			for (int i = 0; i < args.length; i++) {
				// 是否Servlet参数
				boolean isServletArgument = null != args[i]
						&& (args[i] instanceof ServletRequest || args[i] instanceof ServletResponse);
				if (isServletArgument) {
					continue;
				}
				if (i > 0) {
					sb.append(", ");
				}
				if (null == args[i]) {
					sb.append("NULL");
					continue;
				}
				sb.append(JSON.toJSONString(args[i], JSON_CONFIG));
			}
			return sb.toString();
		}
		return "";
	}

	/**
	 * 获取调用方法的名称
	 * 
	 * @param joinPoint
	 * @return
	 */
	private String getInvokeMethodName(JoinPoint joinPoint) {
		Signature signature = joinPoint.getSignature();
		return String.format("%s.%s", signature.getDeclaringTypeName(), signature.getName());
	}

	/**
	 * 效率状态
	 * 
	 * @author djin
	 *
	 */
	private enum SpeedEnum {
		// 正常
		NORMAL,
		// 超时
		TIMEOUT
	}

	/**
	 * 请求状态
	 * 
	 * @author djin
	 */
	private enum RequestEnum {
		// 请求成功
		REQUEST_SUCCESS,
		// 请求错误
		REQUEST_ERROR
	}
}

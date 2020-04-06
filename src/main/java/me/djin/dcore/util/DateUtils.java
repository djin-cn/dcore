/**
 * 
 */
package me.djin.dcore.util;

import java.util.Calendar;
import java.util.Date;

/**
 * @author djin
 * 日期工具类
 */
public class DateUtils extends org.apache.commons.lang3.time.DateUtils {
	/**
	 * 获取一天的开始时间，即0时0分0秒0毫秒
	 * @param date
	 * @return
	 */
	public static Date getStartOfDay(Date date) {
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(date);
		calendar.set(Calendar.HOUR_OF_DAY, 0);
		calendar.set(Calendar.MINUTE, 0);
		calendar.set(Calendar.SECOND, 0);
		calendar.set(Calendar.MILLISECOND, 0);
		return calendar.getTime();
	}
	
	/**
	 * 获取一天的结束时间，即23时59分59秒999毫秒
	 * @param date
	 * @return
	 */
	public static Date getEndOfDay(Date date) {
		date = getStartOfDay(date);
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(date);
		calendar.add(Calendar.DATE, 1);
		calendar.add(Calendar.MILLISECOND, -1);
		return calendar.getTime();
	}
}
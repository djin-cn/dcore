package me.djin.dcore.util;

import java.io.File;

/**
 * 路径工具类
 * 
 * @author djin
 *
 */
public class PathUtil {
	/**
	 * 根据PathUtil类获取Jar包所在目录
	 * 
	 * @return
	 */
	public static String getJarPath() {
		return getJarPath(PathUtil.class);
	}

	/**
	 * 获取Jar包所在目录
	 * 
	 * @param clazz
	 *            jar包内的任意类
	 * @return
	 */
	public static String getJarPath(Class<?> clazz) {
		return clazz.getProtectionDomain().getCodeSource().getLocation().getPath();
	}

	/**
	 * 初始化文件路径，当路径不存在时或者路径所在的文件夹不存在时自动创建文件夹
	 * 
	 * @param filePath
	 *            文件路径
	 * @return
	 */
	public static boolean initPath(String filePath) {
		File file = new File(filePath);
		if (!file.exists()) {
			File dir = file.getParentFile();
			if (!dir.exists()) {
				return dir.mkdirs();
			}
		}
		return true;
	}

	/**
	 * 判断路径是否存在
	 * 
	 * @param filePath
	 *            文件路径
	 * @return
	 */
	public static boolean existPath(String filePath) {
		File file = new File(filePath);
		return file.exists();
	}
}
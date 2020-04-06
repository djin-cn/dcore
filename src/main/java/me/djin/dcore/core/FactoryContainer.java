package me.djin.dcore.core;

import java.util.concurrent.ConcurrentHashMap;

/**
 * 工厂容器类，主要用于解耦对象的创建
 * 
 * @author djin
 *
 */
public class FactoryContainer {
	/**
	 * 容器池
	 */
	private static final ConcurrentHashMap<String, BeanFactory> FACTORIES_POOL = new ConcurrentHashMap<>();

	/**
	 * 添加工厂实例到工厂容器池
	 * 
	 * @param clazz
	 *            继承自BeanFactory接口的工厂接口类
	 * @param factory
	 *            工厂实例
	 * 
	 *            <pre>
	 * 示例:
	     FactoryInterface factory = new FactoryInterfaceImpl();
	     FactoryContainer.addBeanFactory(FactoryInterface.class, factory);
	 *            </pre>
	 */
	public static <T extends BeanFactory> void addBeanFactory(Class<T> clazz, BeanFactory factoryInstance) {
		FACTORIES_POOL.put(clazz.getName(), factoryInstance);
	}

	/**
	 * 从工厂容器池中获取工厂实例
	 * 
	 * @param clazz
	 *            继承自BeanFactory接口的工厂接口类
	 * @return
	 * 
	 *         <pre>
	 * 示例：
	 FactoryInterface factory = FactoryContainer.getBeanFactory(FactoryInterface.class);
	 factory.method(); //method为实际的处理方法，此处只是示例
	 *         </pre>
	 */
	@SuppressWarnings("unchecked")
	public static <T extends BeanFactory> T getBeanFactory(Class<T> clazz) {
		if (clazz == null) {
			return null;
		}
		if (FACTORIES_POOL.isEmpty()) {
			return null;
		}
		return (T)FACTORIES_POOL.getOrDefault(clazz.getName(), null);
	}
}

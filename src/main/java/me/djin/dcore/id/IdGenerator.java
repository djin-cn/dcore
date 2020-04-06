/**
 * 
 */
package me.djin.dcore.id;

/**
 * @author djin
 * ID生成器
 * 
 * 数字类型为最合适的ID类型，存储空间小、有序，比其它类型更合适
 */
public interface IdGenerator {
	/**
	 * 生成ID
	 * @return
	 */
	long nextId();
}
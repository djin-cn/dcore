/**
 * 
 */
package me.djin.dcore.frame.common;

import java.util.Set;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.groups.Default;

import me.djin.dcore.frame.model.Response;

/**
 * @author djin 验证工具类
 */
public class ValidatorUtil {
	private static Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

	/**
	 * 验证数据，如果验证通过则返回null，否则返回Response
	 * @param t
	 * @return
	 */
	public static <T> Response<String> validate(T t) {
		Set<ConstraintViolation<T>> set = validator.validate(t, Default.class);
		if (set != null && !set.isEmpty()) {
			StringBuilder stringBuilder = new StringBuilder();
			for (ConstraintViolation<T> constraintViolation : set) {
				stringBuilder.append(constraintViolation.getPropertyPath().toString()).append(":")
						.append(constraintViolation.getMessage()).append(";");
			}
			return new Response<String>("2", stringBuilder.substring(0, stringBuilder.lastIndexOf(";")).toString());
		}
		return null;
	}
}
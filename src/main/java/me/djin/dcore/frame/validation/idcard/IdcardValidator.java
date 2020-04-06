package me.djin.dcore.frame.validation.idcard;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import me.djin.dcore.util.IdcardUtil;

/**
 * 身份证校验类，支持15位和18位身份证校验
 * 
 * @author djin
 *
 */
public class IdcardValidator implements ConstraintValidator<Idcard, String> {

	@Override
	public void initialize(Idcard constraintAnnotation) {
	}

	@Override
	public boolean isValid(String value, ConstraintValidatorContext context) {
		if(value == null || "".equals(value)) {
			return true;
		}
		IdcardUtil idcard = new IdcardUtil(value);
		return idcard.validate();
	}

}

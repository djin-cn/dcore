package me.djin.dcore.frame.validation.idcard;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import javax.validation.Constraint;
import javax.validation.Payload;

/**
 * 身份证校验注解
 * 
 * @author djin
 *
 */
@Target({ FIELD })
@Retention(RUNTIME)
@Documented
@Constraint(validatedBy = { IdcardValidator.class })
public @interface Idcard {
	String message() default "idcard error";

	Class<?>[] groups() default {};

	Class<? extends Payload>[] payload() default {};
}
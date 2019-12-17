package com.zhm.annotation;



import java.lang.annotation.*;

/**
 *如果你的某些方法需要不经过过滤器，
 * 就需要添加@TokenFilter注解
 * Created by 赵红明 on 2019/9/11.
 */
@Target({ElementType.METHOD,ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface TokenFilter {

}

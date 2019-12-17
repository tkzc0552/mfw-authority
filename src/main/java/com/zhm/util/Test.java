package com.zhm.util;


import com.zhm.dto.Result;
import com.zhm.util.tool.JsonUtil;

import java.util.Map;

/**
 * Created by 赵红明 on 2019/12/4.
 */
public class Test {

    public static void main(String[] args){

        String json= JsonUtil.toJson(Result.sendFailure("xx"));
        System.out.println(json);
        Map result=JsonUtil.fromJson(json,Map.class);
        System.out.println(result);
    }
}

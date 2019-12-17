package com.zhm.dto;

import io.swagger.annotations.ApiModelProperty;

/**
 * 用户登录信息
 * Created by 赵红明 on 2019/7/24.
 */

public class LoginUser {
    @ApiModelProperty(value = "用户Id ")
    private Integer userId;
    @ApiModelProperty(value = "登录名 ")
    private String userName;
    @ApiModelProperty(value = "用户头像")
    private String avataUrl;
    @ApiModelProperty(value = "用户手机")
    private String mobile;


    private String expires;

    public Integer getUserId() {
        return userId;
    }

    public void setUserId(Integer userId) {
        this.userId = userId;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getMobile() {
        return mobile;
    }

    public void setMobile(String mobile) {
        this.mobile = mobile;
    }

    public String getExpires() {
        return expires;
    }

    public void setExpires(String expires) {
        this.expires = expires;
    }

    public String getAvataUrl() {
        return avataUrl;
    }

    public void setAvataUrl(String avataUrl) {
        this.avataUrl = avataUrl;
    }
}

package com.github.yinguoqing96.doraclient.controller;

import cn.hutool.http.HttpUtil;
import com.alibaba.fastjson.JSONObject;
import com.github.yinguoqing96.doraclient.rsa.RSAEncryptUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Yin Guoqing
 * @date 2022/8/20
 */
@RestController
@RequestMapping("/client")
public class ClientController {


    @Value("${rsa.publicKey}")
    private String publicKey;

    @GetMapping("/getMessage")
    public String getMessage() {
        String post = HttpUtil.post("127.0.0.1:9902/api/hello", "");
        JSONObject jsonObject = (JSONObject) JSONObject.parse(post);
        String data = (String) jsonObject.get("data");
        return RSAEncryptUtil.publicKeyDecrypt(data, publicKey);
    }
}
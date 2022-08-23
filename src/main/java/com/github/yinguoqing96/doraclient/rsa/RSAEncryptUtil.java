package com.github.yinguoqing96.doraclient.rsa;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * @author Yin Guoqing
 * @date 2022/8/20
 */
@Slf4j
public class RSAEncryptUtil {

    /**
     * RSA公钥解密
     */
    public static String publicKeyDecrypt(String str, String publicKey) {
        try {
            // base64编码的私钥
            byte[] decoded = Base64.getDecoder().decode(publicKey.getBytes(StandardCharsets.UTF_8));
            PublicKey pubKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(decoded));
            // RSA解密
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, pubKey);
            // 当长度过长的时候，需要分割后解密 128个字节
            String outStr = new String(getMaxResultDecrypt(str, cipher));
            return outStr;
        } catch (Exception e) {
            log.error("Exception: {}", e.getMessage());
        }
        return null;
    }

    private static byte[] getMaxResultDecrypt(String str, Cipher cipher) throws IllegalBlockSizeException, BadPaddingException {
        byte[] inputArray = Base64.getDecoder().decode(str.getBytes(StandardCharsets.UTF_8));
        int inputLength = inputArray.length;
        log.info("{}|解密字节数|inputLength:{}", inputLength);
        // 最大解密字节数，超出最大字节数需要分组加密
        int MAX_ENCRYPT_BLOCK = 128;
        // 标识
        int offSet = 0;
        byte[] resultBytes = {};
        byte[] cache = {};
        while (inputLength - offSet > 0) {
            if (inputLength - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(inputArray, offSet, MAX_ENCRYPT_BLOCK);
                offSet += MAX_ENCRYPT_BLOCK;
            } else {
                cache = cipher.doFinal(inputArray, offSet, inputLength - offSet);
                offSet = inputLength;
            }
            resultBytes = Arrays.copyOf(resultBytes, resultBytes.length + cache.length);
            System.arraycopy(cache, 0, resultBytes, resultBytes.length - cache.length, cache.length);
        }
        return resultBytes;
    }


}
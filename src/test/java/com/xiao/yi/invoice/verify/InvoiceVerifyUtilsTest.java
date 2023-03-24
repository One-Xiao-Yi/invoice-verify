package com.xiao.yi.invoice.verify;

import cn.hutool.core.util.StrUtil;
import org.junit.Test;

import java.io.File;
import java.net.URL;

import static org.junit.Assert.*;

public class InvoiceVerifyUtilsTest {

    @Test
    public void verify() {
        URL resource = InvoiceVerifyUtilsTest.class.getClassLoader().getResource(".");
        String resourcePath = resource.getPath().substring(1);
        File file = new File(resourcePath);

        File[] files = file.listFiles();

        for (File item : files) {
            if (item.isDirectory()) {
                continue;
            }
            try {
                System.out.println(StrUtil.format("文件: {}, 验签结果: {}", item.getName(), String.valueOf(InvoiceVerifyUtils.verify(item))));
            } catch (Exception e) {
                System.out.println(StrUtil.format("文件: {}, 异常结果: {}", item.getName(), e.getMessage()));
            }
        }
    }
}
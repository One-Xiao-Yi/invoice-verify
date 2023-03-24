package com.xiao.yi.invoice.verify;

import com.xiao.yi.invoice.verify.ofd.OFDVerifier;
import com.xiao.yi.invoice.verify.pdf.PDFVerifier;
import org.apache.pdfbox.pdmodel.encryption.SecurityProvider;

import java.io.*;
import java.nio.file.Files;
import java.security.Security;

/**
 * @author xiaoyi
 * @since 2023/3/21
 */
public class InvoiceVerifyUtils {

    static {
        try {
            Security.addProvider(SecurityProvider.getProvider());
        } catch (IOException e) {
            throw new RuntimeException("算法加载失败", e);
        }
    }

    public static boolean verify(String path) {
        File file = new File(path);
        return verify(file);
    }

    public static boolean verify(File file) {
        if (!file.exists()) {
            throw new RuntimeException("文件不存在");
        }

        try (InputStream inputStream = Files.newInputStream(file.toPath());){
            return verify(inputStream, file.getName());
        } catch (IOException e) {
            throw new RuntimeException("打开文件失败", e);
        }
    }

    public static boolean verify(InputStream inputStream, String name) {
        if (name.endsWith(".pdf")) {
            return PDFVerifier.verify(inputStream);
        } else if (name.endsWith(".ofd")) {
            return OFDVerifier.verify(inputStream);
        } else {
            return false;
        }
    }
}

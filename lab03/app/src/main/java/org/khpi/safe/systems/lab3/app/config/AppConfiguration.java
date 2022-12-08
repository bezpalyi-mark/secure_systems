package org.khpi.safe.systems.lab3.app.config;

import org.khpi.safe.systems.lab3.app.security.FileCredentialsManager;
import org.khpi.safe.systems.lab3.app.security.RSAKeyManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

@Configuration
public class AppConfiguration {

    @Value("classpath:public_keys.txt")
    private Resource publicKeysFile;

    @Value("classpath:private_keys.txt")
    private Resource privateKeysFile;

    @Bean
    public FileCredentialsManager fileCredentialsManager() {
        return new FileCredentialsManager();
    }

    @Bean
    public RSAKeyManager rsaKeyManager() {
        return new RSAKeyManager(publicKeysFile, privateKeysFile);
    }
}

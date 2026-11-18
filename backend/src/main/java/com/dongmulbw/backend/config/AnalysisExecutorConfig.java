
package com.dongmulbw.backend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

@Configuration
public class AnalysisExecutorConfig {

    @Bean(name = "analysisExecutor", destroyMethod = "shutdown")
    public Executor analysisExecutor() {
        return Executors.newFixedThreadPool(4);
    }
}

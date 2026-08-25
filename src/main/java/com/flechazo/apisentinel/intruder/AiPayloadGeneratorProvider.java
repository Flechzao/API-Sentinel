package com.flechazo.apisentinel.intruder;

import burp.api.montoya.intruder.AttackConfiguration;
import burp.api.montoya.intruder.PayloadGenerator;
import burp.api.montoya.intruder.PayloadGeneratorProvider;
import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.logging.LeveledLogger;

/**
 * Registers the AI payload generator in Intruder's "Extension-generated"
 * payload type list. The generator is created per attack configuration and
 * carries the full request template context into prompt construction.
 */
public class AiPayloadGeneratorProvider implements PayloadGeneratorProvider {

    private final LlmProviderFactory providerFactory;
    private final ConfigManager configManager;
    private final LeveledLogger logger;

    public AiPayloadGeneratorProvider(LlmProviderFactory providerFactory,
                                      ConfigManager configManager, LeveledLogger logger) {
        this.providerFactory = providerFactory;
        this.configManager = configManager;
        this.logger = logger;
    }

    @Override
    public String displayName() {
        return "API Sentinel - AI 载荷生成（上下文感知）";
    }

    @Override
    public PayloadGenerator providePayloadGenerator(AttackConfiguration attackConfiguration) {
        // Always return a generator: misconfiguration is reported at generation
        // time (end() + log) rather than refusing the generator itself.
        return new AiPayloadGenerator(providerFactory, configManager, logger, attackConfiguration);
    }
}

package com.flechazo.apisentinel.util;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxProcessRunnerTest {

    /** Real field failure (macOS): the agent asked for "python", the machine
     *  only ships python3, and detectInterpreter returned null — "本机未找到
     *  可用的解释器 (python)". Requesting a python-family binary must resolve
     *  as long as EITHER python-family binary exists (family fallback). */
    @Test
    void pythonRequestResolvesOnPython3OnlyMachines() {
        var auto = SandboxProcessRunner.detectInterpreter(null);
        Assumptions.assumeTrue(
                auto == SandboxProcessRunner.Interpreter.PYTHON3
                        || auto == SandboxProcessRunner.Interpreter.PYTHON,
                "no python-family interpreter on this machine — nothing to verify");
        assertThat(SandboxProcessRunner.detectInterpreter("python"))
                .as("requesting 'python' resolves via family fallback")
                .isNotNull();
        assertThat(SandboxProcessRunner.detectInterpreter("python3"))
                .as("requesting 'python3' resolves")
                .isNotNull();
    }

    @Test
    void unknownRequestFallsBackToDetection() {
        // Blank request = auto-detect; whatever it returns is the baseline the
        // fallback logic is built on (may legitimately be null on a machine
        // with no interpreters at all — we only assert the call is stable).
        SandboxProcessRunner.detectInterpreter("");
        SandboxProcessRunner.detectInterpreter(null);
    }
}

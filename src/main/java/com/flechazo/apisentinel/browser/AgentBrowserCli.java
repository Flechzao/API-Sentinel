package com.flechazo.apisentinel.browser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * CLI wrapper for agent-browser commands.
 * Executes agent-browser CLI and returns output.
 */
public class AgentBrowserCli {
    
    private static final String AGENT_BROWSER_CMD = "agent-browser";
    private static final int DEFAULT_TIMEOUT_SECONDS = 30;
    
    /**
     * Execute agent-browser command with arguments.
     * 
     * @param args Command arguments (e.g., "cookies", "--json")
     * @return Command output (stdout)
     * @throws IOException If command fails or times out
     */
    public String execute(String... args) throws IOException {
        List<String> command = new ArrayList<>();
        command.add(AGENT_BROWSER_CMD);
        command.addAll(Arrays.asList(args));
        
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        
        Process process = pb.start();
        
        // Read output
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }
        
        // Wait for completion
        try {
            boolean finished = process.waitFor(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new IOException("Command timed out after " + DEFAULT_TIMEOUT_SECONDS + "s: " + String.join(" ", command));
            }
            
            int exitCode = process.exitValue();
            if (exitCode != 0) {
                throw new IOException("Command failed with exit code " + exitCode + ": " + output);
            }
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Command interrupted: " + String.join(" ", command), e);
        }
        
        return output.toString().trim();
    }
    
    /**
     * Check if agent-browser is installed and accessible.
     * 
     * @return true if agent-browser is available
     */
    public boolean isAvailable() {
        try {
            String version = execute("--version");
            return version != null && !version.isEmpty();
        } catch (IOException e) {
            return false;
        }
    }
    
    /**
     * Get agent-browser version.
     * 
     * @return Version string or null if not available
     */
    public String getVersion() {
        try {
            return execute("--version");
        } catch (IOException e) {
            return null;
        }
    }
    
    /**
     * Install Chrome for agent-browser (first-time setup).
     * 
     * @throws IOException If installation fails
     */
    public void installChrome() throws IOException {
        execute("install");
    }
    
    /**
     * Install Chrome with system dependencies (Linux only).
     * 
     * @throws IOException If installation fails
     */
    public void installChromeWithDeps() throws IOException {
        execute("install", "--with-deps");
    }
    
    /**
     * Run doctor to diagnose agent-browser setup.
     * 
     * @return Doctor output
     * @throws IOException If command fails
     */
    public String doctor() throws IOException {
        return execute("doctor");
    }
}

import { dockerUtil } from '../../utils/docker.js';
import { configUtil } from '../../utils/config.js';
import * as fs from 'fs';
import * as path from 'path';

/**
 * ESLint security scanner for JavaScript/TypeScript code
 */
export class EslintScanner {
  /**
   * Run ESLint security scan on JavaScript/TypeScript code
   * @param codePath Path to the code to scan
   * @param scanDepth Depth of the scan (quick, standard, deep)
   * @returns Array of vulnerabilities found
   */
  async scanCode(
    codePath: string,
    scanDepth: 'quick' | 'standard' | 'deep' = 'standard'
  ): Promise<any[]> {
    console.error(`Running ESLint security scan on ${codePath}`);
    console.error(`Current working directory: ${process.cwd()}`);
    console.error(`Scan depth: ${scanDepth}`);
    
    try {
      // Check if ESLint is enabled in the configuration
      if (!configUtil.isToolEnabled('eslint')) {
        console.error('ESLint scanning is disabled in configuration');
        return [];
      }
      
      // Get the Docker image from configuration - use Node.js 20 for compatibility with latest ESLint
      const dockerImage = configUtil.getToolDockerImage('eslint') || 'node:20-alpine';
      
      // Get the path to the ESLint security configuration
      // Use import.meta.url instead of __dirname since we're in ES modules
      const moduleURL = new URL(import.meta.url);
      const modulePath = path.dirname(moduleURL.pathname);
      const configPath = path.join(modulePath, 'eslint-security-config.json');
      
      console.error(`ESLint config path: ${configPath}`);
      
      // Make sure the configuration file exists
      if (!fs.existsSync(configPath)) {
        throw new Error(`ESLint security configuration file not found: ${configPath}`);
      }
      
      // Determine the scan options based on the scan depth
      const scanOptions = this.getScanOptions(scanDepth);
      
      // Run ESLint in a Docker container
      // Convert relative paths to absolute paths for Docker volume bindings
      const absoluteCodePath = path.resolve(process.cwd(), codePath);
      console.error(`Absolute code path: ${absoluteCodePath}`);
      
      const output = await this.runEslintInDocker(dockerImage, absoluteCodePath, configPath, scanOptions);
      
      // Parse the ESLint output and convert to vulnerabilities
      return this.parseEslintOutput(output, codePath);
    } catch (error) {
      console.error('Error running ESLint security scan:', error);
      throw error;
    }
  }
  
  /**
   * Get scan options based on scan depth
   * @param scanDepth Depth of the scan
   * @returns Scan options
   */
  private getScanOptions(scanDepth: 'quick' | 'standard' | 'deep'): string[] {
    const options: string[] = [];
    
    switch (scanDepth) {
      case 'quick':
        // Quick scan: only check JavaScript files, limit max warnings
        options.push('--ext .js');
        options.push('--max-warnings 10');
        break;
      case 'deep':
        // Deep scan: check all file types, include more rules
        options.push('--ext .js,.ts,.jsx,.tsx');
        options.push('--max-warnings 1000');
        break;
      case 'standard':
      default:
        // Standard scan: check common file types
        options.push('--ext .js,.ts');
        options.push('--max-warnings 100');
        break;
    }
    
    return options;
  }
  
  /**
   * Run ESLint in a Docker container
   * @param dockerImage Docker image to use
   * @param codePath Path to the code to scan
   * @param configPath Path to the ESLint configuration
   * @param options ESLint options
   * @returns ESLint output
   */
  private async runEslintInDocker(
    dockerImage: string,
    codePath: string,
    configPath: string,
    options: string[]
  ): Promise<string> {
    // Get the path to the custom security rules
    const moduleURL = new URL(import.meta.url);
    const modulePath = path.dirname(moduleURL.pathname);
    const customRulesPath = path.join(modulePath, 'custom-security-rules.js');
    
    console.error(`Custom rules path: ${customRulesPath}`);
    
    // Make sure the custom rules file exists
    if (!fs.existsSync(customRulesPath)) {
      throw new Error(`Custom security rules file not found: ${customRulesPath}`);
    }
    
    // Create a temporary directory for our ESLint setup
    const tempDir = path.join(process.cwd(), 'temp-eslint-' + Date.now());
    fs.mkdirSync(tempDir, { recursive: true });
    
    try {
      // Create a package.json for our temporary ESLint setup
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({
        "name": "eslint-security-scanner",
        "version": "1.0.0",
        "type": "commonjs"
      }));
      
      // Create the custom plugin directory structure
      const pluginDir = path.join(tempDir, 'eslint-plugin-custom-security');
      fs.mkdirSync(pluginDir, { recursive: true });
      
      // Copy the custom rules to the plugin directory
      fs.copyFileSync(customRulesPath, path.join(pluginDir, 'index.js'));
      
      // Create a package.json for the custom plugin
      fs.writeFileSync(path.join(pluginDir, 'package.json'), JSON.stringify({
        "name": "eslint-plugin-custom-security",
        "version": "1.0.0",
        "main": "index.js"
      }));
      
      // Create a simple ESLint script that will run our analysis
      const eslintScript = `
const { ESLint } = require('eslint');
const fs = require('fs');

// Load our custom plugin
const customSecurityPlugin = require('./eslint-plugin-custom-security');

async function main() {
  // Initialize ESLint with our config
  const eslint = new ESLint({
    useEslintrc: false,
    overrideConfig: {
      root: true,
      env: {
        node: true,
        es6: true
      },
      parserOptions: {
        ecmaVersion: 2020,
        sourceType: "module"
      },
      plugins: ["security", "custom-security"],
      rules: {
        // Built-in ESLint security rules
        "no-eval": "error",
        "no-implied-eval": "error",
        "no-new-func": "error",
        
        // Custom security rules
        "custom-security/detect-command-injection": "error",
        "custom-security/detect-path-traversal": "error",
        "custom-security/detect-regex-dos": "error",
        "custom-security/detect-code-injection": "error"
      }
    },
    plugins: {
      "custom-security": customSecurityPlugin
    }
  });

  // Run the lint
  const results = await eslint.lintFiles(['/src']);
  
  // Output the results as JSON
  console.log(JSON.stringify(results));
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
      `;
      
      fs.writeFileSync(path.join(tempDir, 'eslint-run.js'), eslintScript);
      
      // Create the ESLint command
      const eslintCommand = [
        'sh', '-c',
        `cd /tmp/eslint && ` +
        `npm init -y && ` +
        `npm install eslint@8.57.0 eslint-plugin-security && ` +
        `node eslint-run.js`
      ];
      
      // Set up volume bindings
      const binds = [
        `${codePath}:/src:ro`,
        `${tempDir}:/tmp/eslint:rw`,
      ];
      
      // Run ESLint in Docker
      return await dockerUtil.runContainer(dockerImage, eslintCommand, binds);
    } finally {
      // Clean up the temporary directory
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch (cleanupError) {
        console.error(`Error cleaning up temporary directory: ${cleanupError}`);
      }
    }
  }
  
  /**
   * Parse ESLint output and convert to vulnerabilities
   * @param output ESLint output
   * @param codePath Path to the code that was scanned
   * @returns Array of vulnerabilities
   */
  private parseEslintOutput(output: string, codePath: string): any[] {
    try {
      // Find the JSON part of the output (it's after all the npm output)
      const jsonStartIndex = output.indexOf('[{');
      if (jsonStartIndex === -1) {
        console.error('No JSON output found in ESLint output');
        console.error('Raw output:', output);
        return [];
      }
      
      const jsonOutput = output.substring(jsonStartIndex);
      console.error(`Extracted JSON output: ${jsonOutput}`);
      
      // Parse the JSON output
      const eslintResults = JSON.parse(jsonOutput);
      
      // Convert ESLint results to vulnerabilities
      const vulnerabilities: any[] = [];
      
      // Process each file result
      for (const fileResult of eslintResults) {
        const filePath = fileResult.filePath.replace('/src', codePath);
        
        // Process each message (issue) in the file
        for (const message of fileResult.messages) {
          // Skip if no rule ID (might be a parsing error)
          if (!message.ruleId) {
            console.error(`Skipping message without rule ID: ${message.message}`);
            continue;
          }
          
          // Map ESLint rule to security issue type
          const vulnType = this.mapRuleToVulnerabilityType(message.ruleId);
          
          // Map ESLint severity to vulnerability severity
          const severity = this.mapSeverity(message.severity);
          
          // Create a unique ID for the vulnerability
          const id = `eslint-${Date.now()}-${vulnerabilities.length + 1}`;
          
          console.error(`Found vulnerability: ${message.ruleId} - ${message.message} at ${filePath}:${message.line}`);
          
          // Get code snippet if available
          const codeSnippet = message.source || '';
          
          // Get remediation advice based on vulnerability type
          const remediation = this.getRemediationAdvice(vulnType, message.ruleId);
          
          // Create the vulnerability object with enhanced information
          vulnerabilities.push({
            id,
            type: vulnType,
            severity,
            location: `${filePath}:${message.line}:${message.column || 0}`,
            description: message.message,
            code_snippet: codeSnippet,
            remediation_advice: remediation,
            recommendation_id: this.getRecommendationId(vulnType),
            rule_id: message.ruleId,
            cwe_id: this.getCweId(vulnType),
            owasp_category: this.getOwaspCategory(vulnType)
          });
        }
      }
      
      return vulnerabilities;
    } catch (error) {
      console.error('Error parsing ESLint output:', error);
      console.error('Raw output:', output);
      return [];
    }
  }
  
  /**
   * Get remediation advice for a vulnerability type
   * @param vulnType Vulnerability type
   * @param ruleId Rule ID that triggered the vulnerability
   * @returns Remediation advice
   */
  private getRemediationAdvice(vulnType: string, ruleId: string): string {
    // Map vulnerability types to remediation advice
    const remediationMap: Record<string, string> = {
      'code_injection': 'Avoid using eval(), Function constructor, or other dynamic code execution methods. Use safer alternatives like JSON.parse() for data parsing.',
      'command_injection': 'Never use unsanitized user input in command execution. Use parameterized commands or command arguments arrays instead of string concatenation.',
      'path_traversal': 'Validate and sanitize file paths. Use path.resolve() to get absolute paths and validate against allowed directories.',
      'regex_dos': 'Avoid patterns with nested quantifiers like (a+)+ which can cause catastrophic backtracking. Use non-backtracking regex engines or limit input length.',
      'xss': 'Use context-appropriate output encoding and content security policies. Consider using templating libraries that automatically escape output.',
      'prototype_pollution': 'Use Object.create(null) for plain objects, avoid using __proto__, and use Object.freeze() to prevent modification of object prototypes.',
      'buffer_overflow': 'Always specify and check buffer lengths. Use safer alternatives like Buffer.alloc() instead of Buffer.allocUnsafe().',
      'weak_cryptography': 'Use modern cryptographic algorithms and libraries. Avoid deprecated methods like MD5 or SHA-1.',
      'timing_attack': 'Use constant-time comparison functions for sensitive operations like password verification.',
      'csrf': 'Implement anti-CSRF tokens for all state-changing operations and validate the token on the server side.',
      'information_exposure': 'Avoid exposing sensitive information in error messages, logs, or responses. Use appropriate error handling.'
    };
    
    return remediationMap[vulnType] || 'Review and fix the security issue according to secure coding best practices.';
  }
  
  /**
   * Get CWE ID for a vulnerability type
   * @param vulnType Vulnerability type
   * @returns CWE ID
   */
  private getCweId(vulnType: string): string {
    // Map vulnerability types to CWE IDs
    const cweMap: Record<string, string> = {
      'code_injection': 'CWE-94', // Code Injection
      'command_injection': 'CWE-77', // Command Injection
      'path_traversal': 'CWE-22', // Path Traversal
      'regex_dos': 'CWE-1333', // Regular Expression Denial of Service
      'xss': 'CWE-79', // Cross-site Scripting
      'prototype_pollution': 'CWE-1321', // Prototype Pollution
      'buffer_overflow': 'CWE-120', // Buffer Overflow
      'weak_cryptography': 'CWE-327', // Use of a Broken or Risky Cryptographic Algorithm
      'timing_attack': 'CWE-208', // Information Exposure Through Timing Discrepancy
      'csrf': 'CWE-352', // Cross-Site Request Forgery
      'information_exposure': 'CWE-200' // Information Exposure
    };
    
    return cweMap[vulnType] || 'CWE-693'; // Protection Mechanism Failure
  }
  
  /**
   * Get OWASP Top 10 category for a vulnerability type
   * @param vulnType Vulnerability type
   * @returns OWASP category
   */
  private getOwaspCategory(vulnType: string): string {
    // Map vulnerability types to OWASP Top 10 2021 categories
    const owaspMap: Record<string, string> = {
      'code_injection': 'A3:2021-Injection',
      'command_injection': 'A3:2021-Injection',
      'path_traversal': 'A1:2021-Broken Access Control',
      'regex_dos': 'A5:2021-Security Misconfiguration',
      'xss': 'A3:2021-Injection',
      'prototype_pollution': 'A8:2021-Software and Data Integrity Failures',
      'buffer_overflow': 'A6:2021-Vulnerable and Outdated Components',
      'weak_cryptography': 'A2:2021-Cryptographic Failures',
      'timing_attack': 'A4:2021-Insecure Design',
      'csrf': 'A1:2021-Broken Access Control',
      'information_exposure': 'A4:2021-Insecure Design'
    };
    
    return owaspMap[vulnType] || 'A4:2021-Insecure Design';
  }
  
  /**
   * Map ESLint rule to vulnerability type
   * @param ruleId ESLint rule ID
   * @returns Vulnerability type
   */
  private mapRuleToVulnerabilityType(ruleId: string): string {
    // Map ESLint security rules to vulnerability types
    const ruleMap: Record<string, string> = {
      // Security plugin rules
      'security/detect-eval-with-expression': 'code_injection',
      'security/detect-non-literal-require': 'code_injection',
      'security/detect-child-process': 'command_injection',
      'security/detect-non-literal-fs-filename': 'path_traversal',
      'security/detect-non-literal-regexp': 'regex_injection',
      'security/detect-unsafe-regex': 'regex_dos',
      'security/detect-buffer-noassert': 'buffer_overflow',
      'security/detect-pseudoRandomBytes': 'weak_cryptography',
      'security/detect-possible-timing-attacks': 'timing_attack',
      'security/detect-no-csrf-before-method-override': 'csrf',
      'security/detect-object-injection': 'prototype_pollution',
      'security/detect-disable-mustache-escape': 'xss',
      
      // Built-in ESLint rules
      'no-eval': 'code_injection',
      'no-implied-eval': 'code_injection',
      'no-new-func': 'code_injection',
      'no-process-env': 'information_exposure',
      'no-process-exit': 'denial_of_service',
      'no-alert': 'information_exposure',
      'no-script-url': 'xss',
      'no-proto': 'prototype_pollution',
      'no-iterator': 'prototype_pollution',
      'no-extend-native': 'prototype_pollution',
      'no-caller': 'code_injection',
      
      // Custom security rules
      'custom-security/detect-command-injection': 'command_injection',
      'custom-security/detect-path-traversal': 'path_traversal',
      'custom-security/detect-regex-dos': 'regex_dos',
      'custom-security/detect-code-injection': 'code_injection'
    };
    
    // Log the rule ID for debugging
    console.error(`Mapping rule ID: ${ruleId} to vulnerability type: ${ruleMap[ruleId] || 'security_issue'}`);
    
    return ruleMap[ruleId] || 'security_issue';
  }
  
  /**
   * Map ESLint severity to vulnerability severity
   * @param eslintSeverity ESLint severity (1 = warning, 2 = error)
   * @returns Vulnerability severity
   */
  private mapSeverity(eslintSeverity: number): string {
    switch (eslintSeverity) {
      case 2:
        return 'high';
      case 1:
        return 'medium';
      default:
        return 'low';
    }
  }
  
  /**
   * Get recommendation ID for a vulnerability type
   * @param vulnType Vulnerability type
   * @returns Recommendation ID
   */
  private getRecommendationId(vulnType: string): string {
    // Map vulnerability types to recommendation IDs
    const recommendationMap: Record<string, string> = {
      'code_injection': 'rec-code-injection-1',
      'command_injection': 'rec-command-injection-1',
      'path_traversal': 'rec-path-traversal-1',
      'regex_injection': 'rec-regex-injection-1',
      'regex_dos': 'rec-regex-dos-1',
      'buffer_overflow': 'rec-buffer-overflow-1',
      'weak_cryptography': 'rec-crypto-1',
      'timing_attack': 'rec-timing-attack-1',
      'csrf': 'rec-csrf-1',
      'prototype_pollution': 'rec-prototype-pollution-1',
      'xss': 'rec-xss-1',
    };
    
    return recommendationMap[vulnType] || 'rec-security-1';
  }
}

// Export singleton instance
export const eslintScanner = new EslintScanner();
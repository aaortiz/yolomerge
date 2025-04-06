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
    
    try {
      // Check if ESLint is enabled in the configuration
      if (!configUtil.isToolEnabled('eslint')) {
        console.error('ESLint scanning is disabled in configuration');
        return [];
      }
      
      // Get the Docker image from configuration
      const dockerImage = configUtil.getToolDockerImage('eslint') || 'node:16-alpine';
      
      // Get the path to the ESLint security configuration
      const configPath = path.join(__dirname, 'eslint-security-config.json');
      
      // Make sure the configuration file exists
      if (!fs.existsSync(configPath)) {
        throw new Error(`ESLint security configuration file not found: ${configPath}`);
      }
      
      // Determine the scan options based on the scan depth
      const scanOptions = this.getScanOptions(scanDepth);
      
      // Run ESLint in a Docker container
      const output = await this.runEslintInDocker(dockerImage, codePath, configPath, scanOptions);
      
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
    // Create the ESLint command
    const eslintCommand = [
      'sh', '-c',
      `npm install -g eslint @typescript-eslint/parser eslint-plugin-security && ` +
      `eslint ${options.join(' ')} --plugin security --no-eslintrc -c /tmp/eslint-config.json /src -f json`
    ];
    
    // Set up volume bindings
    const binds = [
      `${codePath}:/src:ro`,
      `${configPath}:/tmp/eslint-config.json:ro`,
    ];
    
    // Run ESLint in Docker
    return await dockerUtil.runContainer(dockerImage, eslintCommand, binds);
  }
  
  /**
   * Parse ESLint output and convert to vulnerabilities
   * @param output ESLint output
   * @param codePath Path to the code that was scanned
   * @returns Array of vulnerabilities
   */
  private parseEslintOutput(output: string, codePath: string): any[] {
    try {
      // Parse the JSON output
      const eslintResults = JSON.parse(output);
      
      // Convert ESLint results to vulnerabilities
      const vulnerabilities: any[] = [];
      
      // Process each file result
      for (const fileResult of eslintResults) {
        const filePath = fileResult.filePath.replace('/src/', '');
        
        // Process each message (issue) in the file
        for (const message of fileResult.messages) {
          // Map ESLint rule to vulnerability type
          const vulnType = this.mapRuleToVulnerabilityType(message.ruleId);
          
          // Map ESLint severity to vulnerability severity
          const severity = this.mapSeverity(message.severity);
          
          // Create a unique ID for the vulnerability
          const id = `eslint-${Date.now()}-${vulnerabilities.length + 1}`;
          
          // Create the vulnerability object
          vulnerabilities.push({
            id,
            type: vulnType,
            severity,
            location: `${filePath}:${message.line}`,
            description: message.message,
            recommendation_id: this.getRecommendationId(vulnType),
            rule_id: message.ruleId,
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
   * Map ESLint rule to vulnerability type
   * @param ruleId ESLint rule ID
   * @returns Vulnerability type
   */
  private mapRuleToVulnerabilityType(ruleId: string): string {
    // Map ESLint security rules to vulnerability types
    const ruleMap: Record<string, string> = {
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
    };
    
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
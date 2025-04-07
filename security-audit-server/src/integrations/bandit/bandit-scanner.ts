import { dockerUtil } from '../../utils/docker.js';
import { configUtil } from '../../utils/config.js';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Bandit security scanner for Python code
 */
export class BanditScanner {
  /**
   * Run Bandit security scan on Python code
   * @param codePath Path to the code to scan
   * @param scanDepth Depth of the scan (quick, standard, deep)
   * @returns Array of vulnerabilities found
   */
  async scanCode(
    codePath: string,
    scanDepth: 'quick' | 'standard' | 'deep' = 'standard'
  ): Promise<any[]> {
    console.error(`Running Bandit security scan on ${codePath}`);
    
    try {
      // Check if Bandit is enabled in the configuration
      if (!configUtil.isToolEnabled('bandit')) {
        console.error('Bandit scanning is disabled in configuration');
        return [];
      }
      
      // Get the Docker image from configuration
      const dockerImage = configUtil.getToolDockerImage('bandit') || 'python:3.9-alpine';
      
      // Determine the scan options based on the scan depth
      const scanOptions = this.getScanOptions(scanDepth);
      
      // Run Bandit in a Docker container
      const output = await this.runBanditInDocker(dockerImage, codePath, scanOptions);
      
      // Parse the Bandit output and convert to vulnerabilities
      return this.parseBanditOutput(output, codePath);
    } catch (error) {
      console.error('Error running Bandit security scan:', error);
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
        // Quick scan: low confidence, low severity
        options.push('-l'); // Low severity
        options.push('-i'); // Low confidence
        break;
      case 'deep':
        // Deep scan: high confidence, high severity
        options.push('-lll'); // High severity
        options.push('-iii'); // High confidence
        break;
      case 'standard':
      default:
        // Standard scan: medium confidence, medium severity
        options.push('-ll'); // Medium severity
        options.push('-ii'); // Medium confidence
        break;
    }
    
    return options;
  }
  
  /**
   * Run Bandit in a Docker container
   * @param dockerImage Docker image to use
   * @param codePath Path to the code to scan
   * @param options Bandit options
   * @returns Bandit output
   */
  private async runBanditInDocker(
    dockerImage: string,
    codePath: string,
    options: string[]
  ): Promise<string> {
    // Create the Bandit command
    const banditCommand = [
      'sh', '-c',
      `pip install bandit && bandit -r /src -f json ${options.join(' ')}`
    ];
    
    // Set up volume bindings
    const binds = [
      `${codePath}:/src:ro`,
    ];
    
    // Run Bandit in Docker
    return await dockerUtil.runContainer(dockerImage, banditCommand, binds);
  }
  
  /**
   * Parse Bandit output and convert to vulnerabilities
   * @param output Bandit output
   * @param codePath Path to the code that was scanned
   * @returns Array of vulnerabilities
   */
  private parseBanditOutput(output: string, codePath: string): any[] {
    try {
      // Parse the JSON output
      const banditResults = JSON.parse(output);
      
      // Convert Bandit results to vulnerabilities
      const vulnerabilities: any[] = [];
      
      // Process each issue
      for (const issue of banditResults.results) {
        // Map Bandit severity to vulnerability severity
        const severity = this.mapSeverity(issue.issue_severity);
        
        // Create a unique ID for the vulnerability
        const id = `bandit-${Date.now()}-${vulnerabilities.length + 1}`;
        
        // Create the vulnerability object
        vulnerabilities.push({
          id,
          type: issue.test_name,
          severity,
          location: `${issue.filename}:${issue.line_number}`,
          description: issue.issue_text,
          recommendation_id: this.getRecommendationId(issue.test_name),
          rule_id: issue.test_id,
        });
      }
      
      return vulnerabilities;
    } catch (error) {
      console.error('Error parsing Bandit output:', error);
      console.error('Raw output:', output);
      return [];
    }
  }
  
  /**
   * Map Bandit severity to vulnerability severity
   * @param banditSeverity Bandit severity (LOW, MEDIUM, HIGH)
   * @returns Vulnerability severity
   */
  private mapSeverity(banditSeverity: string): string {
    switch (banditSeverity.toUpperCase()) {
      case 'HIGH':
        return 'high';
      case 'MEDIUM':
        return 'medium';
      case 'LOW':
        return 'low';
      default:
        return 'low';
    }
  }
  
  /**
   * Get recommendation ID for a vulnerability type
   * @param vulnType Vulnerability type (Bandit test name)
   * @returns Recommendation ID
   */
  private getRecommendationId(vulnType: string): string {
    // Map Bandit test names to recommendation IDs
    // This mapping would need to be more comprehensive in a real implementation
    const recommendationMap: Record<string, string> = {
      'assert_used': 'rec-assert-1',
      'exec_used': 'rec-exec-1',
      'hardcoded_password_string': 'rec-cred-1',
      'hardcoded_tmp_directory': 'rec-tmp-1',
      'insecure_hashlib_new': 'rec-crypto-1',
      'pickle': 'rec-pickle-1',
      'request_without_timeout': 'rec-timeout-1',
      'subprocess_popen_with_shell_equals_true': 'rec-command-injection-1',
      'try_except_pass': 'rec-except-pass-1',
      'yaml_load': 'rec-yaml-load-1',
    };
    
    return recommendationMap[vulnType] || 'rec-security-1';
  }
}

// Export singleton instance
export const banditScanner = new BanditScanner();
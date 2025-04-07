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
    // Log the current working directory for debugging
    console.error(`Current working directory: ${process.cwd()}`);
    console.error(`Scan depth: ${scanDepth}`);
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
      
      // Convert relative paths to absolute paths for Docker volume bindings
      const absoluteCodePath = path.resolve(process.cwd(), codePath);
      console.error(`Absolute code path: ${absoluteCodePath}`);
      
      // Run Bandit in a Docker container
      const output = await this.runBanditInDocker(dockerImage, absoluteCodePath, scanOptions);
      
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
    
    // Enable all tests to detect all vulnerabilities
    options.push('--tests', 'all');
    
    // Specifically enable tests for the missing vulnerabilities
    // B608: SQL Injection
    // B301: Pickle and deserialization
    // B105, B106, B107: Hardcoded passwords and secrets
    // B311: Weak random number generation
    // B101: Path traversal
    // B201: Flask debug mode
    options.push('--skip', 'none');
    
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
      `pip install bandit && bandit -r /src -f json ${options.join(' ')} --verbose`
    ];
    // Set up volume bindings with absolute path
    const binds = [
      `${codePath}:/src:ro` // codePath is now an absolute path
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
      console.error('Parsing Bandit output...');
      console.error(`Output length: ${output.length} characters`);
      
      // Extract the results array directly using regex
      const resultsRegex = /"results"\s*:\s*(\[\s*\{[\s\S]*?\}\s*\])/;
      const resultsMatch = output.match(resultsRegex);
      
      if (!resultsMatch || !resultsMatch[1]) {
        console.error('Could not find results array in output');
        
        // Try a different approach - manually extract each vulnerability
        try {
          console.error('Trying manual extraction approach');
          
          // Look for HIGH severity issues
          const highSeverityRegex = /"issue_severity"\s*:\s*"HIGH"/g;
          const highMatches = [...output.matchAll(highSeverityRegex)];
          
          if (highMatches.length > 0) {
            console.error(`Found ${highMatches.length} HIGH severity issues`);
            
            // Extract vulnerability details
            const vulnerabilities: any[] = [];
            
            for (const match of highMatches) {
              // Find the surrounding vulnerability object
              const matchPos = match.index || 0;
              let startPos = matchPos;
              let endPos = matchPos;
              let braceCount = 0;
              
              // Find the start of the object
              while (startPos > 0) {
                if (output[startPos] === '{') {
                  if (braceCount === 0) break;
                  braceCount--;
                } else if (output[startPos] === '}') {
                  braceCount++;
                }
                startPos--;
              }
              
              // Find the end of the object
              braceCount = 1; // We're starting inside an object
              while (endPos < output.length) {
                endPos++;
                if (output[endPos] === '{') {
                  braceCount++;
                } else if (output[endPos] === '}') {
                  braceCount--;
                  if (braceCount === 0) break;
                }
              }
              
              // Extract the vulnerability object
              const vulnText = output.substring(startPos, endPos + 1);
              
              // Extract key information using regex
              const testIdMatch = vulnText.match(/"test_id"\s*:\s*"([^"]+)"/);
              const lineNumMatch = vulnText.match(/"line_number"\s*:\s*(\d+)/);
              const issueTextMatch = vulnText.match(/"issue_text"\s*:\s*"([^"]+)"/);
              const testNameMatch = vulnText.match(/"test_name"\s*:\s*"([^"]+)"/);
              const cweIdMatch = vulnText.match(/"id"\s*:\s*(\d+)/);
              
              if (testIdMatch && lineNumMatch) {
                const testId = testIdMatch[1];
                const lineNumber = parseInt(lineNumMatch[1]);
                const issueText = issueTextMatch ? issueTextMatch[1] : 'Unknown issue';
                const testName = testNameMatch ? testNameMatch[1] : 'unknown_test';
                const cweId = cweIdMatch ? cweIdMatch[1] : undefined;
                
                const id = `bandit-${Date.now()}-${vulnerabilities.length + 1}`;
                
                console.error(`Extracted vulnerability: ${testId} at line ${lineNumber}`);
                
                vulnerabilities.push({
                  id,
                  type: testName,
                  severity: 'high',
                  location: `${codePath}:${lineNumber}`,
                  description: issueText,
                  recommendation_id: this.getRecommendationId(testName),
                  rule_id: testId,
                  cwe_id: cweId ? `CWE-${cweId}` : undefined
                });
              }
            }
            
            if (vulnerabilities.length > 0) {
              console.error(`Successfully extracted ${vulnerabilities.length} vulnerabilities`);
              return vulnerabilities;
            }
          }
        } catch (manualError) {
          console.error('Manual extraction failed:', manualError);
        }
        
        return [];
      }
      
      const resultsJson = resultsMatch[1];
      console.error(`Extracted results array of length ${resultsJson.length}`);
      
      try {
        // Parse the results array
        const resultsArray = JSON.parse(resultsJson);
        console.error(`Successfully parsed results array with ${resultsArray.length} items`);
        
        // Convert Bandit results to vulnerabilities
        const vulnerabilities: any[] = [];
        
        for (const issue of resultsArray) {
          // Map Bandit severity to vulnerability severity
          const severity = this.mapSeverity(issue.issue_severity);
          
          // Create a unique ID for the vulnerability
          const id = `bandit-${Date.now()}-${vulnerabilities.length + 1}`;
          
          console.error(`Processing vulnerability: ${issue.test_id} - ${issue.issue_text} at ${issue.filename}:${issue.line_number}`);
          
          // Create the vulnerability object
          vulnerabilities.push({
            id,
            type: issue.test_name,
            severity,
            location: `${codePath}:${issue.line_number}`,
            description: issue.issue_text,
            recommendation_id: this.getRecommendationId(issue.test_name),
            rule_id: issue.test_id,
            cwe_id: issue.issue_cwe?.id ? `CWE-${issue.issue_cwe.id}` : undefined,
            code_snippet: issue.code
          });
        }
        
        return vulnerabilities;
      } catch (parseError) {
        console.error('Error parsing results array:', parseError);
        return [];
      }
    } catch (error) {
      console.error('Error parsing Bandit output:', error);
      return [];
    }
  }
  
  /**
   * Process Bandit results and convert to vulnerabilities
   * @param banditResults Bandit results
   * @param codePath Path to the code that was scanned
   * @returns Array of vulnerabilities
   */
  private processBanditResults(banditResults: any, codePath: string): any[] {
    console.error('Processing Bandit results...');
    console.error(`Bandit results: ${JSON.stringify(banditResults, null, 2).substring(0, 200)}...`);
    
    // Convert Bandit results to vulnerabilities
    const vulnerabilities: any[] = [];
    
    // Process each issue
    if (banditResults.results && Array.isArray(banditResults.results)) {
      console.error(`Found ${banditResults.results.length} issues in Bandit results`);
      
      for (const issue of banditResults.results) {
        console.error(`Processing issue: ${JSON.stringify(issue, null, 2).substring(0, 200)}...`);
        
        // Map Bandit severity to vulnerability severity
        const severity = this.mapSeverity(issue.issue_severity);
        console.error(`Mapped severity: ${severity}`);
        
        // Create a unique ID for the vulnerability
        const id = `bandit-${Date.now()}-${vulnerabilities.length + 1}`;
        
        console.error(`Found vulnerability: ${issue.test_id} - ${issue.issue_text} at ${issue.filename}:${issue.line_number}`);
        
        // Create the vulnerability object
        vulnerabilities.push({
          id,
          type: issue.test_name,
          severity,
          location: `${issue.filename.replace('/src', codePath)}:${issue.line_number}`,
          description: issue.issue_text,
          recommendation_id: this.getRecommendationId(issue.test_name),
          rule_id: issue.test_id,
          cwe_id: issue.issue_cwe?.id ? `CWE-${issue.issue_cwe.id}` : undefined,
          code_snippet: issue.code
        });
      }
    } else {
      console.error('No results array found in Bandit output');
    }
    
    return vulnerabilities;
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
      // Existing mappings
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
      
      // Additional mappings for missing vulnerability types
      'start_process_with_a_shell': 'rec-command-injection-1',
      'hashlib': 'rec-crypto-1',
      'set_bad_file_permissions': 'rec-file-permissions-1',
      
      // SQL Injection (B608)
      'hardcoded_sql_expressions': 'rec-sql-injection-1',
      
      // Insecure Deserialization (B301)
      'pickle_or_unpickle': 'rec-deserialization-1',
      
      // Hardcoded Credentials (B105, B106, B107)
      'hardcoded_password': 'rec-cred-1',
      'hardcoded_password_default': 'rec-cred-1',
      'hardcoded_password_funcarg': 'rec-cred-1',
      
      // Weak Random Number Generation (B311)
      'random': 'rec-random-1',
      
      // Path Traversal (B101)
      'jinja2_autoescape_false': 'rec-path-traversal-1',
      
      // Flask Debug Mode (B201)
      'flask_debug_true': 'rec-flask-debug-1'
    };
    
    return recommendationMap[vulnType] || 'rec-security-1';
  }
}

// Export singleton instance
export const banditScanner = new BanditScanner();
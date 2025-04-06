import { dockerUtil } from '../utils/docker.js';
import { configUtil } from '../utils/config.js';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Static code analysis tool implementation
 */
export class StaticAnalysisTool {
  /**
   * Perform static code analysis on a codebase
   * @param codePath Path to the codebase to scan
   * @param languages Languages to scan (javascript, typescript, python, java)
   * @param scanDepth Depth of the scan (quick, standard, deep)
   * @returns The scan results
   */
  async scanCode(
    codePath: string,
    languages?: string[],
    scanDepth: 'quick' | 'standard' | 'deep' = 'standard'
  ): Promise<any> {
    console.error(`Starting static code analysis for ${codePath}`);
    console.error(`Languages: ${languages ? languages.join(', ') : 'auto-detect'}`);
    console.error(`Scan depth: ${scanDepth}`);
    
    // Validate the code path
    if (!fs.existsSync(codePath)) {
      throw new Error(`Code path does not exist: ${codePath}`);
    }
    
    // Auto-detect languages if not specified
    if (!languages || languages.length === 0) {
      languages = this.detectLanguages(codePath);
      console.error(`Auto-detected languages: ${languages.join(', ')}`);
    }
    
    // Initialize results
    const results: any = {
      scan_id: `static-${Date.now()}`,
      scan_type: 'static_analysis',
      timestamp: new Date().toISOString(),
      code_path: codePath,
      languages: languages,
      scan_depth: scanDepth,
      vulnerabilities: [],
    };
    
    // Scan each language
    for (const language of languages) {
      try {
        const languageResults = await this.scanLanguage(codePath, language, scanDepth);
        results.vulnerabilities.push(...languageResults);
      } catch (error) {
        console.error(`Error scanning ${language}:`, error);
      }
    }
    
    // Calculate summary statistics
    const criticalCount = results.vulnerabilities.filter((v: any) => v.severity === 'critical').length;
    const highCount = results.vulnerabilities.filter((v: any) => v.severity === 'high').length;
    const mediumCount = results.vulnerabilities.filter((v: any) => v.severity === 'medium').length;
    const lowCount = results.vulnerabilities.filter((v: any) => v.severity === 'low').length;
    
    results.vulnerabilities_count = results.vulnerabilities.length;
    results.critical = criticalCount;
    results.high = highCount;
    results.medium = mediumCount;
    results.low = lowCount;
    
    // Generate summary
    results.summary = `Found ${results.vulnerabilities_count} security issues`;
    if (criticalCount > 0) {
      results.summary += ` including ${criticalCount} critical`;
      if (highCount > 0) results.summary += ` and ${highCount} high severity`;
      results.summary += ` vulnerabilities`;
    } else if (highCount > 0) {
      results.summary += ` including ${highCount} high severity vulnerabilities`;
    }
    
    console.error(`Static code analysis completed with ${results.vulnerabilities_count} vulnerabilities found`);
    
    return results;
  }

  /**
   * Detect languages used in the codebase
   * @param codePath Path to the codebase
   * @returns Array of detected languages
   */
  private detectLanguages(codePath: string): string[] {
    const languages = new Set<string>();
    
    // Simple language detection based on file extensions
    const jsFiles = this.countFiles(codePath, ['.js', '.jsx']);
    const tsFiles = this.countFiles(codePath, ['.ts', '.tsx']);
    const pyFiles = this.countFiles(codePath, ['.py']);
    const javaFiles = this.countFiles(codePath, ['.java']);
    
    if (jsFiles > 0) languages.add('javascript');
    if (tsFiles > 0) languages.add('typescript');
    if (pyFiles > 0) languages.add('python');
    if (javaFiles > 0) languages.add('java');
    
    // Default to JavaScript if no languages detected
    if (languages.size === 0) {
      languages.add('javascript');
    }
    
    return Array.from(languages);
  }

  /**
   * Count files with specific extensions in a directory
   * @param dirPath Directory path
   * @param extensions Array of file extensions to count
   * @returns Number of files with the specified extensions
   */
  private countFiles(dirPath: string, extensions: string[]): number {
    let count = 0;
    
    try {
      const entries = fs.readdirSync(dirPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);
        
        if (entry.isDirectory()) {
          // Skip node_modules and other common directories to avoid excessive scanning
          if (['node_modules', '.git', 'dist', 'build', 'target'].includes(entry.name)) {
            continue;
          }
          
          count += this.countFiles(fullPath, extensions);
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();
          if (extensions.includes(ext)) {
            count++;
          }
        }
      }
    } catch (error) {
      console.error(`Error counting files in ${dirPath}:`, error);
    }
    
    return count;
  }

  /**
   * Scan a specific language
   * @param codePath Path to the codebase
   * @param language Language to scan
   * @param scanDepth Depth of the scan
   * @returns Array of vulnerabilities
   */
  private async scanLanguage(
    codePath: string,
    language: string,
    scanDepth: 'quick' | 'standard' | 'deep'
  ): Promise<any[]> {
    console.error(`Scanning ${language} code in ${codePath}`);
    
    switch (language) {
      case 'javascript':
      case 'typescript':
        return await this.scanJavaScript(codePath, scanDepth);
      case 'python':
        return await this.scanPython(codePath, scanDepth);
      case 'java':
        return await this.scanJava(codePath, scanDepth);
      default:
        console.error(`Unsupported language: ${language}`);
        return [];
    }
  }

  /**
   * Scan JavaScript/TypeScript code
   * @param codePath Path to the codebase
   * @param scanDepth Depth of the scan
   * @returns Array of vulnerabilities
   */
  private async scanJavaScript(
    codePath: string,
    scanDepth: 'quick' | 'standard' | 'deep'
  ): Promise<any[]> {
    if (!configUtil.isToolEnabled('eslint')) {
      console.error('ESLint scanning is disabled');
      return [];
    }
    
    try {
      // In a real implementation, this would run ESLint with security plugins
      // For now, we'll simulate the scan with mock results
      
      // Simulate different scan depths
      const scanTimeout = this.getScanTimeout(scanDepth);
      await new Promise(resolve => setTimeout(resolve, Math.random() * 1000)); // Simulate scan time
      
      // For demo purposes, return mock vulnerabilities
      return [
        {
          id: `js-vuln-${Date.now()}-1`,
          type: 'cross_site_scripting',
          severity: 'critical',
          location: `${codePath}/src/components/UserInput.js:42`,
          description: 'Unsanitized user input is directly rendered to the DOM',
          recommendation_id: 'rec-xss-1',
        },
        {
          id: `js-vuln-${Date.now()}-2`,
          type: 'sql_injection',
          severity: 'high',
          location: `${codePath}/src/services/database.js:78`,
          description: 'SQL query is constructed using string concatenation with user input',
          recommendation_id: 'rec-sqli-1',
        },
        {
          id: `js-vuln-${Date.now()}-3`,
          type: 'insecure_direct_object_reference',
          severity: 'high',
          location: `${codePath}/src/controllers/UserController.js:105`,
          description: 'User ID is taken directly from request parameters without authorization check',
          recommendation_id: 'rec-idor-1',
        },
      ];
    } catch (error) {
      console.error('Error scanning JavaScript/TypeScript:', error);
      return [];
    }
  }

  /**
   * Scan Python code
   * @param codePath Path to the codebase
   * @param scanDepth Depth of the scan
   * @returns Array of vulnerabilities
   */
  private async scanPython(
    codePath: string,
    scanDepth: 'quick' | 'standard' | 'deep'
  ): Promise<any[]> {
    if (!configUtil.isToolEnabled('bandit')) {
      console.error('Bandit scanning is disabled');
      return [];
    }
    
    try {
      // In a real implementation, this would run Bandit
      // For now, we'll simulate the scan with mock results
      
      // Simulate different scan depths
      const scanTimeout = this.getScanTimeout(scanDepth);
      await new Promise(resolve => setTimeout(resolve, Math.random() * 1000)); // Simulate scan time
      
      // For demo purposes, return mock vulnerabilities
      return [
        {
          id: `py-vuln-${Date.now()}-1`,
          type: 'command_injection',
          severity: 'critical',
          location: `${codePath}/app/utils/system.py:23`,
          description: 'OS command injection through unsanitized user input',
          recommendation_id: 'rec-cmdi-1',
        },
        {
          id: `py-vuln-${Date.now()}-2`,
          type: 'weak_cryptography',
          severity: 'medium',
          location: `${codePath}/app/security/crypto.py:45`,
          description: 'Use of weak cryptographic algorithm (MD5)',
          recommendation_id: 'rec-crypto-1',
        },
      ];
    } catch (error) {
      console.error('Error scanning Python:', error);
      return [];
    }
  }

  /**
   * Scan Java code
   * @param codePath Path to the codebase
   * @param scanDepth Depth of the scan
   * @returns Array of vulnerabilities
   */
  private async scanJava(
    codePath: string,
    scanDepth: 'quick' | 'standard' | 'deep'
  ): Promise<any[]> {
    if (!configUtil.isToolEnabled('spotbugs')) {
      console.error('SpotBugs scanning is disabled');
      return [];
    }
    
    try {
      // In a real implementation, this would run SpotBugs with Find Security Bugs
      // For now, we'll simulate the scan with mock results
      
      // Simulate different scan depths
      const scanTimeout = this.getScanTimeout(scanDepth);
      await new Promise(resolve => setTimeout(resolve, Math.random() * 1000)); // Simulate scan time
      
      // For demo purposes, return mock vulnerabilities
      return [
        {
          id: `java-vuln-${Date.now()}-1`,
          type: 'path_traversal',
          severity: 'high',
          location: `${codePath}/src/main/java/com/example/FileService.java:67`,
          description: 'Path traversal vulnerability in file access',
          recommendation_id: 'rec-path-1',
        },
        {
          id: `java-vuln-${Date.now()}-2`,
          type: 'insecure_random',
          severity: 'medium',
          location: `${codePath}/src/main/java/com/example/SecurityUtils.java:31`,
          description: 'Use of java.util.Random instead of SecureRandom',
          recommendation_id: 'rec-random-1',
        },
        {
          id: `java-vuln-${Date.now()}-3`,
          type: 'xxe',
          severity: 'high',
          location: `${codePath}/src/main/java/com/example/XmlParser.java:22`,
          description: 'XML External Entity (XXE) vulnerability in XML parsing',
          recommendation_id: 'rec-xxe-1',
        },
      ];
    } catch (error) {
      console.error('Error scanning Java:', error);
      return [];
    }
  }

  /**
   * Get the scan timeout based on scan depth
   * @param scanDepth Depth of the scan
   * @returns Timeout in seconds
   */
  private getScanTimeout(scanDepth: 'quick' | 'standard' | 'deep'): number {
    const baseTimeout = configUtil.getScanTimeout('static');
    
    switch (scanDepth) {
      case 'quick':
        return baseTimeout / 2;
      case 'deep':
        return baseTimeout * 2;
      case 'standard':
      default:
        return baseTimeout;
    }
  }
}

// Export singleton instance
export const staticAnalysisTool = new StaticAnalysisTool();

import { configUtil } from '../utils/config.js';
import { eslintScanner } from '../integrations/eslint/eslint-scanner.js';
import { banditScanner } from '../integrations/bandit/bandit-scanner.js';
import { spotbugsScanner } from '../integrations/spotbugs/spotbugs-scanner.js';
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
        console.error(`Language ${language} scan results: ${JSON.stringify(languageResults, null, 2).substring(0, 200)}...`);
        console.error(`Found ${languageResults.length} vulnerabilities for language ${language}`);
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
    
    let results: any[] = [];
    
    switch (language) {
      case 'javascript':
      case 'typescript':
        results = await eslintScanner.scanCode(codePath, scanDepth);
        console.error(`ESLint scanner returned ${results.length} vulnerabilities`);
        break;
      case 'python':
        console.error(`Calling Bandit scanner for ${codePath}`);
        results = await banditScanner.scanCode(codePath, scanDepth);
        console.error(`Bandit scanner returned ${results ? results.length : 0} vulnerabilities`);
        console.error(`Bandit scanner results: ${JSON.stringify(results, null, 2).substring(0, 200)}...`);
        break;
      case 'java':
        results = await spotbugsScanner.scanCode(codePath, scanDepth);
        console.error(`SpotBugs scanner returned ${results.length} vulnerabilities`);
        break;
      default:
        console.error(`Unsupported language: ${language}`);
        break;
    }
    
    return results || [];
  }

  // Removed scanJavaScript, scanPython, and scanJava methods as they are now handled by the integration modules
  
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

import { dockerUtil } from '../utils/docker.js';
import { configUtil } from '../utils/config.js';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Dependency scanning tool implementation
 */
export class DependencyScanTool {
  /**
   * Scan project dependencies for known vulnerabilities
   * @param projectPath Path to the project to scan
   * @param packageManager Package manager type (npm, pip, maven)
   * @returns The scan results
   */
  async scanDependencies(
    projectPath: string,
    packageManager?: 'npm' | 'pip' | 'maven'
  ): Promise<any> {
    console.error(`Starting dependency scan for ${projectPath}`);
    console.error(`Package manager: ${packageManager || 'auto-detect'}`);
    
    // Validate the project path
    if (!fs.existsSync(projectPath)) {
      throw new Error(`Project path does not exist: ${projectPath}`);
    }
    
    // Auto-detect package manager if not specified
    if (!packageManager) {
      packageManager = this.detectPackageManager(projectPath);
      console.error(`Auto-detected package manager: ${packageManager || 'unknown'}`);
    }
    
    // Initialize results
    const results: any = {
      scan_id: `deps-${Date.now()}`,
      scan_type: 'dependency_scan',
      timestamp: new Date().toISOString(),
      project_path: projectPath,
      package_manager: packageManager,
      vulnerabilities: [],
    };
    
    // Scan dependencies based on package manager
    try {
      if (packageManager) {
        const vulnerabilities = await this.scanPackageManager(projectPath, packageManager);
        results.vulnerabilities = vulnerabilities;
      } else {
        // Try all supported package managers
        const npmVulns = await this.scanPackageManager(projectPath, 'npm');
        const pipVulns = await this.scanPackageManager(projectPath, 'pip');
        const mavenVulns = await this.scanPackageManager(projectPath, 'maven');
        
        results.vulnerabilities = [
          ...npmVulns,
          ...pipVulns,
          ...mavenVulns,
        ];
      }
    } catch (error) {
      console.error(`Error scanning dependencies:`, error);
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
    results.summary = `Found ${results.vulnerabilities_count} vulnerable dependencies`;
    if (criticalCount > 0) {
      results.summary += ` including ${criticalCount} critical`;
      if (highCount > 0) results.summary += ` and ${highCount} high severity`;
      results.summary += ` issues`;
    } else if (highCount > 0) {
      results.summary += ` including ${highCount} high severity issues`;
    }
    
    console.error(`Dependency scan completed with ${results.vulnerabilities_count} vulnerabilities found`);
    
    return results;
  }

  /**
   * Detect package manager used in the project
   * @param projectPath Path to the project
   * @returns Detected package manager or undefined
   */
  private detectPackageManager(projectPath: string): 'npm' | 'pip' | 'maven' | undefined {
    // Check for package.json (npm/yarn)
    if (fs.existsSync(path.join(projectPath, 'package.json'))) {
      return 'npm';
    }
    
    // Check for requirements.txt or setup.py (pip)
    if (
      fs.existsSync(path.join(projectPath, 'requirements.txt')) ||
      fs.existsSync(path.join(projectPath, 'setup.py'))
    ) {
      return 'pip';
    }
    
    // Check for pom.xml (maven)
    if (fs.existsSync(path.join(projectPath, 'pom.xml'))) {
      return 'maven';
    }
    
    // No supported package manager detected
    return undefined;
  }

  /**
   * Scan dependencies using a specific package manager
   * @param projectPath Path to the project
   * @param packageManager Package manager to use
   * @returns Array of vulnerabilities
   */
  private async scanPackageManager(
    projectPath: string,
    packageManager: 'npm' | 'pip' | 'maven'
  ): Promise<any[]> {
    console.error(`Scanning dependencies with ${packageManager}`);
    
    switch (packageManager) {
      case 'npm':
        return await this.scanNpmDependencies(projectPath);
      case 'pip':
        return await this.scanPipDependencies(projectPath);
      case 'maven':
        return await this.scanMavenDependencies(projectPath);
      default:
        return [];
    }
  }

  /**
   * Scan npm dependencies
   * @param projectPath Path to the project
   * @returns Array of vulnerabilities
   */
  private async scanNpmDependencies(projectPath: string): Promise<any[]> {
    if (!configUtil.isToolEnabled('dependencyCheck')) {
      console.error('Dependency-Check scanning is disabled');
      return [];
    }
    
    try {
      // In a real implementation, this would run npm audit or OWASP Dependency-Check
      // For now, we'll simulate the scan with mock results
      
      await new Promise(resolve => setTimeout(resolve, Math.random() * 1000)); // Simulate scan time
      
      // For demo purposes, return mock vulnerabilities
      return [
        {
          id: `npm-vuln-${Date.now()}-1`,
          package: 'lodash',
          version: '4.17.15',
          severity: 'high',
          vulnerability: 'Prototype Pollution',
          cve: 'CVE-2020-8203',
          description: 'Prototype pollution vulnerability in lodash < 4.17.19',
          recommendation_id: 'rec-dep-1',
        },
        {
          id: `npm-vuln-${Date.now()}-2`,
          package: 'axios',
          version: '0.19.0',
          severity: 'medium',
          vulnerability: 'Server-Side Request Forgery',
          cve: 'CVE-2020-28168',
          description: 'SSRF vulnerability in axios < 0.21.1',
          recommendation_id: 'rec-dep-2',
        },
        {
          id: `npm-vuln-${Date.now()}-3`,
          package: 'express',
          version: '4.16.0',
          severity: 'medium',
          vulnerability: 'Denial of Service',
          cve: 'CVE-2019-10768',
          description: 'DoS vulnerability in express < 4.17.1',
          recommendation_id: 'rec-dep-3',
        },
      ];
    } catch (error) {
      console.error('Error scanning npm dependencies:', error);
      return [];
    }
  }

  /**
   * Scan pip dependencies
   * @param projectPath Path to the project
   * @returns Array of vulnerabilities
   */
  private async scanPipDependencies(projectPath: string): Promise<any[]> {
    if (!configUtil.isToolEnabled('dependencyCheck')) {
      console.error('Dependency-Check scanning is disabled');
      return [];
    }
    
    try {
      // In a real implementation, this would run safety or OWASP Dependency-Check
      // For now, we'll simulate the scan with mock results
      
      await new Promise(resolve => setTimeout(resolve, Math.random() * 1000)); // Simulate scan time
      
      // For demo purposes, return mock vulnerabilities
      return [
        {
          id: `pip-vuln-${Date.now()}-1`,
          package: 'django',
          version: '2.2.0',
          severity: 'high',
          vulnerability: 'SQL Injection',
          cve: 'CVE-2020-9402',
          description: 'SQL injection vulnerability in Django < 2.2.10',
          recommendation_id: 'rec-dep-4',
        },
        {
          id: `pip-vuln-${Date.now()}-2`,
          package: 'flask',
          version: '1.0.0',
          severity: 'medium',
          vulnerability: 'Information Disclosure',
          cve: 'CVE-2019-1010083',
          description: 'Information disclosure vulnerability in Flask < 1.0.3',
          recommendation_id: 'rec-dep-5',
        },
      ];
    } catch (error) {
      console.error('Error scanning pip dependencies:', error);
      return [];
    }
  }

  /**
   * Scan maven dependencies
   * @param projectPath Path to the project
   * @returns Array of vulnerabilities
   */
  private async scanMavenDependencies(projectPath: string): Promise<any[]> {
    if (!configUtil.isToolEnabled('dependencyCheck')) {
      console.error('Dependency-Check scanning is disabled');
      return [];
    }
    
    try {
      // In a real implementation, this would run OWASP Dependency-Check
      // For now, we'll simulate the scan with mock results
      
      await new Promise(resolve => setTimeout(resolve, Math.random() * 1000)); // Simulate scan time
      
      // For demo purposes, return mock vulnerabilities
      return [
        {
          id: `maven-vuln-${Date.now()}-1`,
          package: 'org.apache.struts:struts2-core',
          version: '2.5.16',
          severity: 'critical',
          vulnerability: 'Remote Code Execution',
          cve: 'CVE-2018-11776',
          description: 'RCE vulnerability in Apache Struts 2.5 < 2.5.17',
          recommendation_id: 'rec-dep-6',
        },
        {
          id: `maven-vuln-${Date.now()}-2`,
          package: 'com.fasterxml.jackson.core:jackson-databind',
          version: '2.9.8',
          severity: 'high',
          vulnerability: 'Deserialization of Untrusted Data',
          cve: 'CVE-2019-12086',
          description: 'Deserialization vulnerability in jackson-databind < 2.9.9',
          recommendation_id: 'rec-dep-7',
        },
      ];
    } catch (error) {
      console.error('Error scanning maven dependencies:', error);
      return [];
    }
  }
}

// Export singleton instance
export const dependencyScanTool = new DependencyScanTool();
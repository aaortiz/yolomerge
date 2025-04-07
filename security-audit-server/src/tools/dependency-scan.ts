import { configUtil } from '../utils/config.js';
import * as fs from 'fs';
import * as path from 'path';
import { dependencyCheckScanner } from '../integrations/dependency-check/dependency-check-scanner.js'; // Import the new scanner

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
    console.error(`Scanning npm dependencies using Dependency-Check for path: ${projectPath}`);
    // Ensure projectPath is absolute for Docker volume mounting
    const absoluteProjectPath = path.resolve(projectPath);
    return await dependencyCheckScanner.scan(absoluteProjectPath, 'npm');
  }

  /**
   * Scan pip dependencies
   * @param projectPath Path to the project
   * @returns Array of vulnerabilities
   */
  private async scanPipDependencies(projectPath: string): Promise<any[]> {
    console.error(`Scanning pip dependencies using Dependency-Check for path: ${projectPath}`);
    // Ensure projectPath is absolute for Docker volume mounting
    const absoluteProjectPath = path.resolve(projectPath);
    return await dependencyCheckScanner.scan(absoluteProjectPath, 'pip');
  }

  /**
   * Scan maven dependencies
   * @param projectPath Path to the project
   * @returns Array of vulnerabilities
   */
  private async scanMavenDependencies(projectPath: string): Promise<any[]> {
    console.error(`Scanning maven dependencies using Dependency-Check for path: ${projectPath}`);
    // Ensure projectPath is absolute for Docker volume mounting
    const absoluteProjectPath = path.resolve(projectPath);
    return await dependencyCheckScanner.scan(absoluteProjectPath, 'maven');
  }
}

// Export singleton instance
export const dependencyScanTool = new DependencyScanTool();
import { dockerUtil } from '../../utils/docker.js';
import { configUtil } from '../../utils/config.js';
import * as path from 'path';
import * as fs from 'fs';

/**
 * Interface for Dependency-Check vulnerability report item
 */
interface DependencyCheckVulnerability {
  name: string;
  severity: string;
  cwe?: string;
  description: string;
  identifiers?: { name: string }[];
  packages?: { id: string; confidence: string }[];
}

/**
 * Interface for Dependency-Check report structure
 */
interface DependencyCheckReport {
  dependencies?: {
    packages?: { id: string }[];
    vulnerabilities?: DependencyCheckVulnerability[];
  }[];
}

/**
 * Runs OWASP Dependency-Check using Docker
 */
export class DependencyCheckScanner {
  /**
   * Scans a project using OWASP Dependency-Check.
   * @param projectPath Absolute path to the project directory.
   * @param packageManager The package manager type ('npm', 'pip', 'maven').
   * @returns Array of vulnerabilities found.
   */
  async scan(projectPath: string, packageManager: 'npm' | 'pip' | 'maven'): Promise<any[]> {
    if (!configUtil.isToolEnabled('dependencyCheck')) {
      console.error('Dependency-Check scanning is disabled in config.');
      return [];
    }

    const dockerImage = configUtil.getToolDockerImage('dependencyCheck');
    if (!dockerImage) {
      console.error('Dependency-Check Docker image not configured.');
      return [];
    }

    const scanDir = '/scan';
    const reportDir = '/report';
    const reportFile = 'dependency-check-report.json';
    const reportPath = path.join(reportDir, reportFile);

    // Ensure the host report directory exists (Docker requires it for mounting)
    // We'll use a temporary directory within the project for simplicity
    const hostReportDir = path.join(projectPath, '.security-audit-reports');
    if (!fs.existsSync(hostReportDir)) {
      fs.mkdirSync(hostReportDir, { recursive: true });
    }
    const hostReportPath = path.join(hostReportDir, reportFile);


    // Base Docker command arguments
    const baseArgs = [
      '--scan', scanDir,
      '--format', 'JSON',
      '--out', reportDir,
      '--project', `project-${packageManager}`, // Project name for the report
      '--failOnCVSS', '0', // Don't fail the build based on score
      '--prettyPrint',
      // Add NVD API key if configured (recommended for performance)
      // '--nvdApiKey', 'YOUR_NVD_API_KEY',
      // Add RetireJS integration if needed for JS projects
      // '--enableExperimental',
    ];

    // Add package manager specific arguments if necessary
    // Dependency-Check usually auto-detects based on files present
    // Example: '--nodeAuditAnalyzerEnabled', 'true' for npm audit integration

    // Construct command array for runContainer
    const cmd = [...baseArgs];

    // Construct binds array for runContainer
    const binds = [
      `${projectPath}:${scanDir}:ro`, // Mount project read-only
      `${hostReportDir}:${reportDir}`   // Mount report directory read-write
    ];

    console.error(`Running Dependency-Check container with image: ${dockerImage}`);
    console.error(`Command: ${cmd.join(' ')}`);
    console.error(`Binds: ${binds.join(', ')}`);

    try {
      // Execute the Docker command using runContainer
      console.error(`[DepCheckScanner] Executing Docker container...`);
      const timeoutSeconds = configUtil.getScanTimeout('dependency');
      // Note: runContainer doesn't have a timeout parameter, timeout needs handling if required.
      // The output from runContainer is the container logs, not the report content directly.
      const containerLogs = await dockerUtil.runContainer(dockerImage, cmd, binds);
      console.error("[DepCheckScanner] Docker execution finished.");
      // console.error("Dependency-Check container logs:", containerLogs); // Optional: Log full container output if needed for debugging


      // Check if the report file was created on the host
      console.error(`[DepCheckScanner] Checking for report file at: ${hostReportPath}`);
      if (!fs.existsSync(hostReportPath)) {
        console.error(`Dependency-Check report file not found at: ${hostReportPath}`);
        return [];
      }

      // Read and parse the report
      console.error(`[DepCheckScanner] Reading report file...`);
      const reportContent = fs.readFileSync(hostReportPath, 'utf-8');
      // console.error(`[DepCheckScanner] Raw report content:\n${reportContent}`); // Optional: Log raw report
      const report: DependencyCheckReport = JSON.parse(reportContent);
      console.error(`[DepCheckScanner] Report parsed successfully.`);

      // Clean up the report file and directory
      fs.unlinkSync(hostReportPath);
      // Only remove dir if empty, handle potential errors
      try {
        fs.rmdirSync(hostReportDir);
      } catch (rmdirError) {
         console.warn(`Could not remove report directory ${hostReportDir}: ${rmdirError}`);
      }


      // Process the report to extract vulnerabilities
      const vulnerabilities = this.parseReport(report);
      console.error(`[DepCheckScanner] Parsed ${vulnerabilities.length} vulnerabilities from report.`);
      return vulnerabilities;

    } catch (error) {
      console.error('Error running OWASP Dependency-Check:', error);
       // Clean up report file/dir on error too
       if (fs.existsSync(hostReportPath)) fs.unlinkSync(hostReportPath);
       if (fs.existsSync(hostReportDir)) {
         try { fs.rmdirSync(hostReportDir); } catch (e) {}
       }
      return []; // Return empty array on error
    }
  }

  /**
   * Parses the Dependency-Check JSON report to extract vulnerabilities.
   * @param report The parsed JSON report object.
   * @returns Array of formatted vulnerability objects.
   */
  private parseReport(report: DependencyCheckReport): any[] {
    const vulnerabilities: any[] = [];
    if (!report.dependencies) {
      return vulnerabilities;
    }

    report.dependencies.forEach(dep => {
      if (dep.vulnerabilities) {
        dep.vulnerabilities.forEach(vuln => {
          const cve = vuln.identifiers?.find(id => id.name.startsWith('CVE-'))?.name;
          const packageName = dep.packages?.[0]?.id || 'unknown'; // Get package identifier

          vulnerabilities.push({
            id: `depcheck-${vuln.name}-${Date.now()}`, // Generate a unique ID
            package: packageName,
            // version: 'N/A', // Version might be part of the package ID or need extraction
            severity: vuln.severity.toLowerCase(),
            vulnerability: vuln.name, // Often the CVE or internal ID
            cve: cve || vuln.name, // Use CVE if available
            description: vuln.description,
            recommendation_id: `rec-dep-${cve || vuln.name}`, // Generate recommendation ID
          });
        });
      }
    });

    return vulnerabilities;
  }
}

// Export singleton instance
export const dependencyCheckScanner = new DependencyCheckScanner();
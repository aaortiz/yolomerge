import { reportGenerator } from '../utils/report.js';
import { configUtil } from '../utils/config.js';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Report generation tool implementation
 */
export class ReportGeneratorTool {
  // Directory to store scan results
  private scanResultsDir: string;
  
  constructor() {
    // Create a directory to store scan results
    this.scanResultsDir = path.join(process.cwd(), 'scan-results');
    if (!fs.existsSync(this.scanResultsDir)) {
      fs.mkdirSync(this.scanResultsDir, { recursive: true });
    }
    console.error(`Scan results directory: ${this.scanResultsDir}`);
  }
  
  /**
   * Store scan results for later report generation
   * @param scanId The ID of the scan
   * @param results The scan results
   */
  storeScanResults(scanId: string, results: any): void {
    // Write scan results to a file
    const filePath = path.join(this.scanResultsDir, `${scanId}.json`);
    fs.writeFileSync(filePath, JSON.stringify(results, null, 2));
    console.error(`Stored scan results for scan ID: ${scanId} in file: ${filePath}`);
  }
  
  /**
   * Generate a security report
   * @param scanId The ID of the scan to generate a report for
   * @param format The report format (text, json, html, pdf)
   * @returns The generated report
   */
  async generateReport(
    scanId: string,
    format: 'text' | 'json' | 'html' | 'pdf' = 'text'
  ): Promise<any> {
    console.error(`Generating ${format} report for scan ID: ${scanId}`);
    
    // Get scan results
    const scanResults = this.getScanResults(scanId);
    if (!scanResults) {
      throw new Error(`No scan results found for scan ID: ${scanId}`);
    }
    
    // Generate report
    const reportContent = reportGenerator.generateReport(scanId, scanResults, format);
    
    // Create report ID
    const reportId = `report-${Date.now()}`;
    
    // Save report to temporary file if needed
    let reportFilePath: string | undefined;
    if (format !== 'text') {
      reportFilePath = this.saveReportToFile(reportId, reportContent, format);
    }
    
    // Return report metadata
    return {
      report_id: reportId,
      scan_id: scanId,
      format: format,
      generated_at: new Date().toISOString(),
      summary: scanResults.summary || 'Security audit report generated successfully',
      report_content: format === 'text' ? reportContent : undefined,
      report_file: reportFilePath,
    };
  }
  
  /**
   * Get scan results by ID
   * @param scanId The ID of the scan
   * @returns The scan results or undefined if not found
   */
  public getScanResults(scanId: string): any {
    // Check if we have the results in a file
    const filePath = path.join(this.scanResultsDir, `${scanId}.json`);
    if (fs.existsSync(filePath)) {
      try {
        const fileContent = fs.readFileSync(filePath, 'utf-8');
        const scanResults = JSON.parse(fileContent);
        console.error(`Found vulnerability data for scan ID: ${scanId} in file: ${filePath}`);
        return scanResults;
      } catch (error) {
        console.error(`Error reading scan results from file: ${filePath}`, error);
      }
    }
    
    // If results are not found, return undefined
    console.error(`Scan results not found for scan ID: ${scanId}`);
    return undefined;
  }
  
  /**
   * Generate mock results for a scan ID
   * @param scanId The ID of the scan
   * @returns Mock scan results
   */
  private generateMockResults(scanId: string): any {
    if (scanId.startsWith('static-')) {
      return {
        scan_id: scanId,
        scan_type: 'static_analysis',
        timestamp: new Date().toISOString(),
        vulnerabilities_count: 5,
        critical: 1,
        high: 2,
        medium: 1,
        low: 1,
        summary: "Found 5 security issues including 1 critical XSS vulnerability",
        vulnerabilities: [
          {
            id: "vuln-1",
            type: "cross_site_scripting",
            severity: "critical",
            location: "src/components/UserInput.js:42",
            description: "Unsanitized user input is directly rendered to the DOM",
            recommendation_id: "rec-xss-1",
          },
          {
            id: "vuln-2",
            type: "sql_injection",
            severity: "high",
            location: "src/services/database.js:78",
            description: "SQL query is constructed using string concatenation with user input",
            recommendation_id: "rec-sqli-1",
          },
          {
            id: "vuln-3",
            type: "insecure_direct_object_reference",
            severity: "high",
            location: "src/controllers/UserController.js:105",
            description: "User ID is taken directly from request parameters without authorization check",
            recommendation_id: "rec-idor-1",
          },
          {
            id: "vuln-4",
            type: "insecure_configuration",
            severity: "medium",
            location: "config/server.js:12",
            description: "Debug mode is enabled in production environment",
            recommendation_id: "rec-config-1",
          },
          {
            id: "vuln-5",
            type: "hardcoded_credentials",
            severity: "low",
            location: "src/utils/apiClient.js:8",
            description: "API key is hardcoded in source code",
            recommendation_id: "rec-cred-1",
          },
        ],
      };
    } else if (scanId.startsWith('deps-')) {
      return {
        scan_id: scanId,
        scan_type: 'dependency_scan',
        timestamp: new Date().toISOString(),
        vulnerabilities_count: 3,
        critical: 0,
        high: 1,
        medium: 2,
        low: 0,
        summary: "Found 3 vulnerable dependencies including 1 high severity issue",
        vulnerabilities: [
          {
            id: "dep-1",
            package: "lodash",
            version: "4.17.15",
            severity: "high",
            vulnerability: "Prototype Pollution",
            cve: "CVE-2020-8203",
            recommendation_id: "rec-dep-1",
          },
          {
            id: "dep-2",
            package: "axios",
            version: "0.19.0",
            severity: "medium",
            vulnerability: "Server-Side Request Forgery",
            cve: "CVE-2020-28168",
            recommendation_id: "rec-dep-2",
          },
          {
            id: "dep-3",
            package: "express",
            version: "4.16.0",
            severity: "medium",
            vulnerability: "Denial of Service",
            cve: "CVE-2019-10768",
            recommendation_id: "rec-dep-3",
          },
        ],
      };
    } else if (scanId.startsWith('live-')) {
      return {
        scan_id: scanId,
        scan_type: 'dynamic_testing',
        timestamp: new Date().toISOString(),
        vulnerabilities_count: 3,
        critical: 0,
        high: 1,
        medium: 2,
        low: 0,
        summary: "Found 3 security issues including 1 high severity CSRF vulnerability",
        vulnerabilities: [
          {
            id: "dyn-1",
            type: "cross_site_request_forgery",
            severity: "high",
            endpoint: "/api/user/update",
            description: "No CSRF token validation on state-changing operation",
            recommendation_id: "rec-csrf-1",
          },
          {
            id: "dyn-2",
            type: "missing_security_headers",
            severity: "medium",
            endpoint: "/*",
            description: "Content-Security-Policy header is not set",
            recommendation_id: "rec-header-1",
          },
          {
            id: "dyn-3",
            type: "information_disclosure",
            severity: "medium",
            endpoint: "/api/error",
            description: "Detailed error messages expose stack traces",
            recommendation_id: "rec-info-1",
          },
        ],
      };
    } else if (scanId.startsWith('compliance-')) {
      return {
        scan_id: scanId,
        scan_type: 'compliance_check',
        timestamp: new Date().toISOString(),
        standard: 'owasp-top-10',
        compliance_score: 70,
        passing_checks: 7,
        failing_checks: 3,
        summary: "OWASP TOP 10 compliance score: 70% (7/10 checks passing)",
        compliance_checks: [
          {
            id: "A01:2021",
            name: "Broken Access Control",
            status: "fail",
            details: "Found 2 instances of improper access control",
          },
          {
            id: "A02:2021",
            name: "Cryptographic Failures",
            status: "pass",
            details: "No cryptographic issues detected",
          },
          {
            id: "A03:2021",
            name: "Injection",
            status: "fail",
            details: "Found 1 SQL injection vulnerability",
          },
          {
            id: "A04:2021",
            name: "Insecure Design",
            status: "pass",
            details: "No insecure design patterns detected",
          },
          {
            id: "A05:2021",
            name: "Security Misconfiguration",
            status: "pass",
            details: "No security misconfigurations detected",
          },
          {
            id: "A06:2021",
            name: "Vulnerable and Outdated Components",
            status: "fail",
            details: "Found 3 vulnerable dependencies",
          },
          {
            id: "A07:2021",
            name: "Identification and Authentication Failures",
            status: "pass",
            details: "Authentication mechanisms are secure",
          },
          {
            id: "A08:2021",
            name: "Software and Data Integrity Failures",
            status: "pass",
            details: "No integrity issues detected",
          },
          {
            id: "A09:2021",
            name: "Security Logging and Monitoring Failures",
            status: "pass",
            details: "Logging and monitoring are adequate",
          },
          {
            id: "A10:2021",
            name: "Server-Side Request Forgery (SSRF)",
            status: "pass",
            details: "No SSRF vulnerabilities detected",
          },
        ],
      };
    } else {
      return {
        scan_id: scanId,
        scan_type: 'unknown',
        timestamp: new Date().toISOString(),
        summary: "Unknown scan type",
      };
    }
  }
  
  /**
   * Save report to a temporary file
   * @param reportId The ID of the report
   * @param content The report content
   * @param format The report format
   * @returns The path to the saved file
   */
  private saveReportToFile(reportId: string, content: string, format: string): string {
    // Create reports directory if it doesn't exist
    const reportsDir = path.join('/tmp', 'security-audit-reports');
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }
    
    // Determine file extension
    const extension = format === 'json' ? 'json' : format === 'html' ? 'html' : format === 'pdf' ? 'pdf' : 'txt';
    
    // Create file path
    const filePath = path.join(reportsDir, `${reportId}.${extension}`);
    
    // Write content to file
    fs.writeFileSync(filePath, content);
    
    console.error(`Report saved to ${filePath}`);
    
    return filePath;
  }
}

// Export singleton instance
export const reportGeneratorTool = new ReportGeneratorTool();
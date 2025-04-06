/**
 * Report generation utility for security audit results
 */
export class ReportGenerator {
  /**
   * Generate a security report in the specified format
   * @param scanId The ID of the scan
   * @param scanResults The scan results
   * @param format The report format (text, json, html, pdf)
   * @returns The generated report
   */
  generateReport(
    scanId: string,
    scanResults: any,
    format: 'text' | 'json' | 'html' | 'pdf' = 'text'
  ): string {
    switch (format) {
      case 'json':
        return this.generateJsonReport(scanId, scanResults);
      case 'html':
        return this.generateHtmlReport(scanId, scanResults);
      case 'pdf':
        return this.generatePdfReport(scanId, scanResults);
      case 'text':
      default:
        return this.generateTextReport(scanId, scanResults);
    }
  }

  /**
   * Generate a text report
   * @param scanId The ID of the scan
   * @param scanResults The scan results
   * @returns The generated text report
   */
  private generateTextReport(scanId: string, scanResults: any): string {
    const timestamp = new Date().toISOString();
    let report = '';

    report += '=======================================================\n';
    report += '             SECURITY AUDIT REPORT                     \n';
    report += '=======================================================\n\n';
    report += `Scan ID: ${scanId}\n`;
    report += `Generated: ${timestamp}\n`;
    report += `Scan Type: ${this.getScanType(scanId)}\n\n`;

    report += '-------------------------------------------------------\n';
    report += 'SUMMARY\n';
    report += '-------------------------------------------------------\n\n';
    
    if (scanResults.summary) {
      report += `${scanResults.summary}\n\n`;
    }
    
    if (scanResults.vulnerabilities_count !== undefined) {
      report += `Total Vulnerabilities: ${scanResults.vulnerabilities_count}\n`;
      if (scanResults.critical !== undefined) report += `Critical: ${scanResults.critical}\n`;
      if (scanResults.high !== undefined) report += `High: ${scanResults.high}\n`;
      if (scanResults.medium !== undefined) report += `Medium: ${scanResults.medium}\n`;
      if (scanResults.low !== undefined) report += `Low: ${scanResults.low}\n`;
    }
    
    report += '\n';

    // Add vulnerabilities details if available
    if (scanResults.vulnerabilities && Array.isArray(scanResults.vulnerabilities)) {
      report += '-------------------------------------------------------\n';
      report += 'VULNERABILITIES\n';
      report += '-------------------------------------------------------\n\n';
      
      scanResults.vulnerabilities.forEach((vuln: any, index: number) => {
        report += `[${index + 1}] `;
        
        if (vuln.type) report += `${vuln.type.toUpperCase()}`;
        else if (vuln.package) report += `VULNERABLE DEPENDENCY: ${vuln.package}`;
        
        report += '\n';
        
        if (vuln.severity) report += `Severity: ${vuln.severity}\n`;
        if (vuln.location) report += `Location: ${vuln.location}\n`;
        if (vuln.endpoint) report += `Endpoint: ${vuln.endpoint}\n`;
        if (vuln.package) report += `Package: ${vuln.package}\n`;
        if (vuln.version) report += `Version: ${vuln.version}\n`;
        if (vuln.cve) report += `CVE: ${vuln.cve}\n`;
        if (vuln.description) report += `Description: ${vuln.description}\n`;
        
        report += '\n';
      });
    }

    // Add compliance checks if available
    if (scanResults.compliance_checks && Array.isArray(scanResults.compliance_checks)) {
      report += '-------------------------------------------------------\n';
      report += 'COMPLIANCE CHECKS\n';
      report += '-------------------------------------------------------\n\n';
      
      scanResults.compliance_checks.forEach((check: any) => {
        report += `${check.id} - ${check.name}\n`;
        report += `Status: ${check.status.toUpperCase()}\n`;
        if (check.details) report += `Details: ${check.details}\n`;
        report += '\n';
      });
    }

    report += '=======================================================\n';
    report += 'RECOMMENDATIONS\n';
    report += '=======================================================\n\n';
    
    report += 'For detailed remediation steps, access the recommendation resources:\n';
    if (scanResults.vulnerabilities && Array.isArray(scanResults.vulnerabilities)) {
      scanResults.vulnerabilities.forEach((vuln: any) => {
        if (vuln.recommendation_id) {
          report += `- security://recommendations/${vuln.recommendation_id}\n`;
        }
      });
    }
    
    report += '\n';
    report += '=======================================================\n';
    report += 'END OF REPORT\n';
    report += '=======================================================\n';

    return report;
  }

  /**
   * Generate a JSON report
   * @param scanId The ID of the scan
   * @param scanResults The scan results
   * @returns The generated JSON report
   */
  private generateJsonReport(scanId: string, scanResults: any): string {
    const report = {
      report_id: `report-${Date.now()}`,
      scan_id: scanId,
      scan_type: this.getScanType(scanId),
      timestamp: new Date().toISOString(),
      results: scanResults,
    };
    
    return JSON.stringify(report, null, 2);
  }

  /**
   * Generate an HTML report
   * @param scanId The ID of the scan
   * @param scanResults The scan results
   * @returns The generated HTML report
   */
  private generateHtmlReport(scanId: string, scanResults: any): string {
    const timestamp = new Date().toISOString();
    const scanType = this.getScanType(scanId);
    
    let vulnerabilitiesHtml = '';
    if (scanResults.vulnerabilities && Array.isArray(scanResults.vulnerabilities)) {
      scanResults.vulnerabilities.forEach((vuln: any, index: number) => {
        let vulnTitle = '';
        if (vuln.type) vulnTitle = vuln.type.toUpperCase();
        else if (vuln.package) vulnTitle = `VULNERABLE DEPENDENCY: ${vuln.package}`;
        
        let vulnDetails = '';
        if (vuln.severity) vulnDetails += `<p><strong>Severity:</strong> ${this.getSeverityBadge(vuln.severity)}</p>`;
        if (vuln.location) vulnDetails += `<p><strong>Location:</strong> ${vuln.location}</p>`;
        if (vuln.endpoint) vulnDetails += `<p><strong>Endpoint:</strong> ${vuln.endpoint}</p>`;
        if (vuln.package) vulnDetails += `<p><strong>Package:</strong> ${vuln.package}</p>`;
        if (vuln.version) vulnDetails += `<p><strong>Version:</strong> ${vuln.version}</p>`;
        if (vuln.cve) vulnDetails += `<p><strong>CVE:</strong> <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.cve}" target="_blank">${vuln.cve}</a></p>`;
        if (vuln.description) vulnDetails += `<p><strong>Description:</strong> ${vuln.description}</p>`;
        
        vulnerabilitiesHtml += `
          <div class="vulnerability">
            <h3>[${index + 1}] ${vulnTitle}</h3>
            ${vulnDetails}
          </div>
        `;
      });
    }
    
    let complianceHtml = '';
    if (scanResults.compliance_checks && Array.isArray(scanResults.compliance_checks)) {
      scanResults.compliance_checks.forEach((check: any) => {
        const statusClass = check.status === 'pass' ? 'status-pass' : 'status-fail';
        
        complianceHtml += `
          <div class="compliance-check">
            <h3>${check.id} - ${check.name}</h3>
            <p><strong>Status:</strong> <span class="${statusClass}">${check.status.toUpperCase()}</span></p>
            ${check.details ? `<p><strong>Details:</strong> ${check.details}</p>` : ''}
          </div>
        `;
      });
    }
    
    let recommendationsHtml = '';
    if (scanResults.vulnerabilities && Array.isArray(scanResults.vulnerabilities)) {
      scanResults.vulnerabilities.forEach((vuln: any) => {
        if (vuln.recommendation_id) {
          recommendationsHtml += `<li>security://recommendations/${vuln.recommendation_id}</li>`;
        }
      });
    }
    
    return `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Audit Report - ${scanId}</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
          }
          h1, h2 {
            color: #2c3e50;
          }
          .header {
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
          }
          .summary {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
          }
          .vulnerability, .compliance-check {
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          }
          .severity-critical {
            background-color: #ff5252;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
          }
          .severity-high {
            background-color: #ff9800;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
          }
          .severity-medium {
            background-color: #ffeb3b;
            color: #333;
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
          }
          .severity-low {
            background-color: #4caf50;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
          }
          .status-pass {
            background-color: #4caf50;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
          }
          .status-fail {
            background-color: #ff5252;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
          }
          .section {
            margin-bottom: 30px;
          }
          .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 10px;
            border-top: 1px solid #ddd;
            font-size: 0.9em;
            color: #777;
          }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>Security Audit Report</h1>
          <p><strong>Scan ID:</strong> ${scanId}</p>
          <p><strong>Generated:</strong> ${timestamp}</p>
          <p><strong>Scan Type:</strong> ${scanType}</p>
        </div>
        
        <div class="section">
          <h2>Summary</h2>
          <div class="summary">
            ${scanResults.summary ? `<p>${scanResults.summary}</p>` : ''}
            
            ${scanResults.vulnerabilities_count !== undefined ? `
              <p><strong>Total Vulnerabilities:</strong> ${scanResults.vulnerabilities_count}</p>
              ${scanResults.critical !== undefined ? `<p><strong>Critical:</strong> ${scanResults.critical}</p>` : ''}
              ${scanResults.high !== undefined ? `<p><strong>High:</strong> ${scanResults.high}</p>` : ''}
              ${scanResults.medium !== undefined ? `<p><strong>Medium:</strong> ${scanResults.medium}</p>` : ''}
              ${scanResults.low !== undefined ? `<p><strong>Low:</strong> ${scanResults.low}</p>` : ''}
            ` : ''}
          </div>
        </div>
        
        ${vulnerabilitiesHtml ? `
          <div class="section">
            <h2>Vulnerabilities</h2>
            ${vulnerabilitiesHtml}
          </div>
        ` : ''}
        
        ${complianceHtml ? `
          <div class="section">
            <h2>Compliance Checks</h2>
            ${complianceHtml}
          </div>
        ` : ''}
        
        ${recommendationsHtml ? `
          <div class="section">
            <h2>Recommendations</h2>
            <p>For detailed remediation steps, access the recommendation resources:</p>
            <ul>
              ${recommendationsHtml}
            </ul>
          </div>
        ` : ''}
        
        <div class="footer">
          <p>Generated by Security Audit MCP Server</p>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate a PDF report
   * @param scanId The ID of the scan
   * @param scanResults The scan results
   * @returns The generated PDF report (as a placeholder)
   */
  private generatePdfReport(scanId: string, scanResults: any): string {
    // In a real implementation, this would generate a PDF
    // For now, return a placeholder message
    return `PDF report generation would require additional dependencies like puppeteer or pdfkit.
For now, please use the HTML report format and convert it to PDF if needed.

Scan ID: ${scanId}
Timestamp: ${new Date().toISOString()}
`;
  }

  /**
   * Get the scan type based on the scan ID
   * @param scanId The scan ID
   * @returns The scan type
   */
  private getScanType(scanId: string): string {
    if (scanId.startsWith('static-')) {
      return 'Static Code Analysis';
    } else if (scanId.startsWith('deps-')) {
      return 'Dependency Vulnerability Scan';
    } else if (scanId.startsWith('live-')) {
      return 'Dynamic Application Security Testing';
    } else if (scanId.startsWith('compliance-')) {
      return 'Compliance Check';
    } else {
      return 'Security Scan';
    }
  }

  /**
   * Get an HTML badge for the severity level
   * @param severity The severity level
   * @returns HTML for the severity badge
   */
  private getSeverityBadge(severity: string): string {
    switch (severity.toLowerCase()) {
      case 'critical':
        return '<span class="severity-critical">CRITICAL</span>';
      case 'high':
        return '<span class="severity-high">HIGH</span>';
      case 'medium':
        return '<span class="severity-medium">MEDIUM</span>';
      case 'low':
        return '<span class="severity-low">LOW</span>';
      default:
        return severity.toUpperCase();
    }
  }
}

// Export singleton instance
export const reportGenerator = new ReportGenerator();
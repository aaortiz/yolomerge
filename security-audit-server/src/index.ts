#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ListToolsRequestSchema,
  McpError,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { staticAnalysisTool } from './tools/static-analysis.js';
import { dependencyScanTool } from './tools/dependency-scan.js';
import { dynamicTestingTool } from './tools/dynamic-testing.js';
import { complianceCheckTool } from './tools/compliance-check.js';
import { reportGeneratorTool } from './tools/report-generator.js';
import { configUtil } from './utils/config.js';

/**
 * Security Audit MCP Server
 * 
 * This server provides security auditing capabilities including:
 * - Static code analysis
 * - Dynamic application security testing
 * - Dependency vulnerability scanning
 * - Compliance checking with security standards
 */
class SecurityAuditServer {
  private server: Server;

  constructor() {
    // Initialize the MCP server
    this.server = new Server(
      {
        name: 'security-audit-server',
        version: '0.1.0',
      },
      {
        capabilities: {
          resources: {},
          tools: {},
        },
      }
    );

    // Set up request handlers
    this.setupToolHandlers();
    this.setupResourceHandlers();
    
    // Error handling
    this.server.onerror = (error) => console.error('[MCP Error]', error);
    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  /**
   * Set up handlers for MCP tools
   */
  private setupToolHandlers() {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'scan_code_security',
          description: 'Performs static code analysis on a codebase',
          inputSchema: {
            type: 'object',
            properties: {
              path: {
                type: 'string',
                description: 'Path to the codebase to scan',
              },
              languages: {
                type: 'array',
                items: {
                  type: 'string',
                  enum: ['javascript', 'typescript', 'python', 'java'],
                },
                description: 'Languages to scan',
              },
              scan_depth: {
                type: 'string',
                enum: ['quick', 'standard', 'deep'],
                description: 'Depth of the scan',
              },
            },
            required: ['path'],
          },
        },
        {
          name: 'scan_dependencies',
          description: 'Scans project dependencies for known vulnerabilities',
          inputSchema: {
            type: 'object',
            properties: {
              path: {
                type: 'string',
                description: 'Path to the project to scan',
              },
              package_manager: {
                type: 'string',
                enum: ['npm', 'pip', 'maven'],
                description: 'Package manager type',
              },
            },
            required: ['path'],
          },
        },
        {
          name: 'scan_live_application',
          description: 'Performs dynamic security testing on a live application',
          inputSchema: {
            type: 'object',
            properties: {
              url: {
                type: 'string',
                description: 'URL of the application to scan',
              },
              scan_type: {
                type: 'string',
                enum: ['passive', 'active'],
                description: 'Type of scan to perform',
              },
              include_apis: {
                type: 'boolean',
                description: 'Whether to include API endpoints in the scan',
              },
            },
            required: ['url'],
          },
        },
        {
          name: 'check_compliance',
          description: 'Checks compliance with security standards',
          inputSchema: {
            type: 'object',
            properties: {
              target: {
                type: 'string',
                description: 'Target to check (code path or application URL)',
              },
              standard: {
                type: 'string',
                enum: ['owasp-top-10', 'pci-dss', 'hipaa', 'gdpr'],
                description: 'Security standard to check against',
              },
            },
            required: ['target', 'standard'],
          },
        },
        {
          name: 'generate_security_report',
          description: 'Generates a comprehensive security report',
          inputSchema: {
            type: 'object',
            properties: {
              scan_id: {
                type: 'string',
                description: 'ID of the scan to generate a report for',
              },
              format: {
                type: 'string',
                enum: ['text', 'json', 'html', 'pdf'],
                description: 'Format of the report',
              },
            },
            required: ['scan_id'],
          },
        },
      ],
    }));

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      switch (request.params.name) {
        case 'scan_code_security':
          return await this.handleStaticCodeScan(request.params.arguments);
        case 'scan_dependencies':
          return await this.handleDependencyScan(request.params.arguments);
        case 'scan_live_application':
          return await this.handleLiveApplicationScan(request.params.arguments);
        case 'check_compliance':
          return await this.handleComplianceCheck(request.params.arguments);
        case 'generate_security_report':
          return await this.handleReportGeneration(request.params.arguments);
        default:
          throw new McpError(
            ErrorCode.MethodNotFound,
            `Unknown tool: ${request.params.name}`
          );
      }
    });
  }

  /**
   * Set up handlers for MCP resources
   */
  private setupResourceHandlers() {
    // List available resources
    this.server.setRequestHandler(ListResourcesRequestSchema, async () => ({
      resources: [
        {
          uri: 'security://standards/owasp-top-10',
          name: 'OWASP Top 10 Security Risks',
          mimeType: 'application/json',
          description: 'Information about the OWASP Top 10 security risks',
        },
      ],
    }));

    // List available resource templates
    this.server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => ({
      resourceTemplates: [
        {
          uriTemplate: 'security://vulnerabilities/{scan_id}',
          name: 'Scan Vulnerabilities',
          mimeType: 'application/json',
          description: 'Detailed information about vulnerabilities found in a scan',
        },
        {
          uriTemplate: 'security://recommendations/{vulnerability_id}',
          name: 'Vulnerability Recommendations',
          mimeType: 'application/json',
          description: 'Remediation recommendations for specific vulnerabilities',
        },
        {
          uriTemplate: 'security://compliance/{standard}',
          name: 'Compliance Information',
          mimeType: 'application/json',
          description: 'Compliance information for specific security standards',
        },
      ],
    }));

    // Handle resource reads
    this.server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      const uri = request.params.uri;
      
      // Handle OWASP Top 10 resource
      if (uri === 'security://standards/owasp-top-10') {
        return {
          contents: [
            {
              uri,
              mimeType: 'application/json',
              text: JSON.stringify(this.getOwaspTop10Data(), null, 2),
            },
          ],
        };
      }
      
      // Handle vulnerability details
      const vulnMatch = uri.match(/^security:\/\/vulnerabilities\/(.+)$/);
      if (vulnMatch) {
        const scanId = vulnMatch[1];
        return {
          contents: [
            {
              uri,
              mimeType: 'application/json',
              text: JSON.stringify(this.getVulnerabilityData(scanId), null, 2),
            },
          ],
        };
      }
      
      // Handle recommendation details
      const recMatch = uri.match(/^security:\/\/recommendations\/(.+)$/);
      if (recMatch) {
        const vulnId = recMatch[1];
        return {
          contents: [
            {
              uri,
              mimeType: 'application/json',
              text: JSON.stringify(this.getRecommendationData(vulnId), null, 2),
            },
          ],
        };
      }
      
      // Handle compliance information
      const compMatch = uri.match(/^security:\/\/compliance\/(.+)$/);
      if (compMatch) {
        const standard = compMatch[1];
        return {
          contents: [
            {
              uri,
              mimeType: 'application/json',
              text: JSON.stringify(this.getComplianceData(standard), null, 2),
            },
          ],
        };
      }
      
      throw new McpError(
        ErrorCode.InvalidRequest,
        `Invalid URI format: ${uri}`
      );
    });
  }

  /**
   * Handle static code security scan
   */
  private async handleStaticCodeScan(args: any) {
    // Validate arguments
    if (!args.path) {
      return {
        content: [
          {
            type: 'text',
            text: 'Error: Path is required for static code scanning',
          },
        ],
        isError: true,
      };
    }

    try {
      // Perform static code analysis
      const scanResults = await staticAnalysisTool.scanCode(
        args.path,
        args.languages,
        args.scan_depth || configUtil.getDefaultStaticScanDepth()
      );
      
      // Store scan results for later report generation
      reportGeneratorTool.storeScanResults(scanResults.scan_id, scanResults);
      
      // Return scan summary
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              scan_id: scanResults.scan_id,
              vulnerabilities_count: scanResults.vulnerabilities_count,
              critical: scanResults.critical,
              high: scanResults.high,
              medium: scanResults.medium,
              low: scanResults.low,
              summary: scanResults.summary,
              details_resource: `security://vulnerabilities/${scanResults.scan_id}`,
            }, null, 2),
          },
        ],
      };
    } catch (error) {
      console.error('Error during static code scan:', error);
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        content: [
          {
            type: 'text',
            text: `Error during static code scan: ${errorMessage}`,
          },
        ],
        isError: true,
      };
    }
  }

  /**
   * Handle dependency scan
   */
  private async handleDependencyScan(args: any) {
    // Validate arguments
    if (!args.path) {
      return {
        content: [
          {
            type: 'text',
            text: 'Error: Path is required for dependency scanning',
          },
        ],
        isError: true,
      };
    }

    try {
      // Perform dependency scan
      const scanResults = await dependencyScanTool.scanDependencies(
        args.path,
        args.package_manager
      );
      
      // Store scan results for later report generation
      reportGeneratorTool.storeScanResults(scanResults.scan_id, scanResults);
      
      // Return scan summary
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              scan_id: scanResults.scan_id,
              vulnerabilities_count: scanResults.vulnerabilities_count,
              critical: scanResults.critical,
              high: scanResults.high,
              medium: scanResults.medium,
              low: scanResults.low,
              summary: scanResults.summary,
              details_resource: `security://vulnerabilities/${scanResults.scan_id}`,
            }, null, 2),
          },
        ],
      };
    } catch (error) {
      console.error('Error during dependency scan:', error);
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        content: [
          {
            type: 'text',
            text: `Error during dependency scan: ${errorMessage}`,
          },
        ],
        isError: true,
      };
    }
  }

  /**
   * Handle live application scan
   */
  private async handleLiveApplicationScan(args: any) {
    // Validate arguments
    if (!args.url) {
      return {
        content: [
          {
            type: 'text',
            text: 'Error: URL is required for live application scanning',
          },
        ],
        isError: true,
      };
    }

    try {
      // Perform dynamic application security testing
      const scanResults = await dynamicTestingTool.scanLiveApplication(
        args.url,
        args.scan_type || configUtil.getDefaultDynamicScanType(),
        args.include_apis || false
      );
      
      // Store scan results for later report generation
      reportGeneratorTool.storeScanResults(scanResults.scan_id, scanResults);
      
      // Return scan summary
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              scan_id: scanResults.scan_id,
              vulnerabilities_count: scanResults.vulnerabilities_count,
              critical: scanResults.critical,
              high: scanResults.high,
              medium: scanResults.medium,
              low: scanResults.low,
              summary: scanResults.summary,
              details_resource: `security://vulnerabilities/${scanResults.scan_id}`,
            }, null, 2),
          },
        ],
      };
    } catch (error) {
      console.error('Error during live application scan:', error);
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        content: [
          {
            type: 'text',
            text: `Error during live application scan: ${errorMessage}`,
          },
        ],
        isError: true,
      };
    }
  }

  /**
   * Handle compliance check
   */
  private async handleComplianceCheck(args: any) {
    // Validate arguments
    if (!args.target || !args.standard) {
      return {
        content: [
          {
            type: 'text',
            text: 'Error: Target and standard are required for compliance checking',
          },
        ],
        isError: true,
      };
    }

    try {
      // Perform compliance check
      const checkResults = await complianceCheckTool.checkCompliance(
        args.target,
        args.standard
      );
      
      // Store scan results for later report generation
      reportGeneratorTool.storeScanResults(checkResults.scan_id, checkResults);
      
      // Return check summary
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              scan_id: checkResults.scan_id,
              standard: checkResults.standard,
              compliance_score: checkResults.compliance_score,
              passing_checks: checkResults.passing_checks,
              failing_checks: checkResults.failing_checks,
              summary: checkResults.summary,
              details_resource: `security://compliance/${checkResults.standard}`,
            }, null, 2),
          },
        ],
      };
    } catch (error) {
      console.error('Error during compliance check:', error);
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        content: [
          {
            type: 'text',
            text: `Error during compliance check: ${errorMessage}`,
          },
        ],
        isError: true,
      };
    }
  }

  /**
   * Handle report generation
   */
  private async handleReportGeneration(args: any) {
    // Validate arguments
    if (!args.scan_id) {
      return {
        content: [
          {
            type: 'text',
            text: 'Error: Scan ID is required for report generation',
          },
        ],
        isError: true,
      };
    }

    try {
      // Generate report
      const reportResult = await reportGeneratorTool.generateReport(
        args.scan_id,
        args.format || configUtil.getDefaultReportFormat()
      );
      
      // Return report metadata
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              report_id: reportResult.report_id,
              scan_id: reportResult.scan_id,
              format: reportResult.format,
              generated_at: reportResult.generated_at,
              summary: reportResult.summary,
              report_content: reportResult.report_content,
              report_file: reportResult.report_file,
            }, null, 2),
          },
        ],
      };
    } catch (error) {
      console.error('Error during report generation:', error);
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        content: [
          {
            type: 'text',
            text: `Error during report generation: ${errorMessage}`,
          },
        ],
        isError: true,
      };
    }
  }

  /**
   * Get OWASP Top 10 data
   */
  private getOwaspTop10Data() {
    return {
      title: "OWASP Top 10 - 2021",
      description: "The OWASP Top 10 is a standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications.",
      risks: [
        {
          id: "A01:2021",
          name: "Broken Access Control",
          description: "Access control enforces policy such that users cannot act outside of their intended permissions.",
        },
        {
          id: "A02:2021",
          name: "Cryptographic Failures",
          description: "Failures related to cryptography which often lead to sensitive data exposure or system compromise.",
        },
        {
          id: "A03:2021",
          name: "Injection",
          description: "Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query.",
        },
        {
          id: "A04:2021",
          name: "Insecure Design",
          description: "Insecure design refers to risks related to design and architectural flaws.",
        },
        {
          id: "A05:2021",
          name: "Security Misconfiguration",
          description: "Security misconfiguration is the most commonly seen issue, often resulting from insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information.",
        },
        {
          id: "A06:2021",
          name: "Vulnerable and Outdated Components",
          description: "Components, such as libraries, frameworks, and other software modules, run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover.",
        },
        {
          id: "A07:2021",
          name: "Identification and Authentication Failures",
          description: "Authentication failures related to the user's identity, authentication, and session management.",
        },
        {
          id: "A08:2021",
          name: "Software and Data Integrity Failures",
          description: "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations.",
        },
        {
          id: "A09:2021",
          name: "Security Logging and Monitoring Failures",
          description: "This category helps detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected.",
        },
        {
          id: "A10:2021",
          name: "Server-Side Request Forgery (SSRF)",
          description: "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL.",
        },
      ],
    };
  }

  /**
   * Get vulnerability data for a scan
   */
  private getVulnerabilityData(scanId: string) {
    // Try to get actual scan results from the report generator
    // In a real implementation, this would retrieve the stored scan results
    // For now, we'll just use mock data
    try {
      // This is a placeholder for retrieving stored scan results
      // In a real implementation, you would call a method to get the stored results
      const scanResults = undefined;
      if (scanResults) {
        return scanResults;
      }
    } catch (error) {
      console.error(`Error retrieving scan results for ${scanId}:`, error);
    }
    
    // Fall back to mock data based on the scan ID
    if (scanId.startsWith('static-')) {
      return {
        scan_id: scanId,
        scan_type: "static_analysis",
        timestamp: new Date().toISOString(),
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
        scan_type: "dependency_scan",
        timestamp: new Date().toISOString(),
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
        scan_type: "dynamic_testing",
        timestamp: new Date().toISOString(),
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
    } else {
      return {
        error: "Unknown scan ID",
      };
    }
  }

  /**
   * Get recommendation data for a vulnerability
   */
  private getRecommendationData(vulnId: string) {
    // In a real implementation, this would retrieve actual recommendations
    // For now, return mock data based on the vulnerability ID
    
    const recommendations: Record<string, any> = {
      "rec-xss-1": {
        id: "rec-xss-1",
        title: "Prevent Cross-Site Scripting (XSS)",
        description: "Always sanitize user input before rendering it to the DOM",
        remediation_steps: [
          "Use React's JSX escaping",
          "Implement a content security policy",
          "Sanitize user input with libraries like DOMPurify",
          "Use the 'textContent' property instead of 'innerHTML'",
        ],
        code_example: "// Instead of:\nelem.innerHTML = userInput;\n\n// Use:\nelem.textContent = userInput;\n\n// Or with React:\nreturn <div>{userInput}</div>;",
        references: [
          "https://owasp.org/www-community/attacks/xss/",
          "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
      },
      "rec-sqli-1": {
        id: "rec-sqli-1",
        title: "Prevent SQL Injection",
        description: "Use parameterized queries or prepared statements instead of string concatenation",
        remediation_steps: [
          "Use parameterized queries",
          "Use an ORM (Object-Relational Mapping) library",
          "Apply input validation",
          "Implement least privilege database accounts",
        ],
        code_example: "// Instead of:\ndb.query(`SELECT * FROM users WHERE username = '${username}'`);\n\n// Use:\ndb.query('SELECT * FROM users WHERE username = ?', [username]);",
        references: [
          "https://owasp.org/www-community/attacks/SQL_Injection",
          "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
      },
      // Add more recommendations as needed
    };
    
    return recommendations[vulnId] || { error: "Unknown vulnerability ID" };
  }

  /**
   * Get compliance data for a standard
   */
  private getComplianceData(standard: string) {
    // In a real implementation, this would retrieve actual compliance data
    // For now, return mock data based on the standard
    
    if (standard === 'owasp-top-10') {
      return {
        standard: "OWASP Top 10 - 2021",
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
        error: "Compliance data not available for the specified standard",
      };
    }
  }

  /**
   * Run the server
   */
  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Security Audit MCP server running on stdio');
  }
}

// Create and run the server
const server = new SecurityAuditServer();
server.run().catch(console.error);
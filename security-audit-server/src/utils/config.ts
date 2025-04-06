/**
 * Configuration utility for the security audit MCP server
 */
export class ConfigUtil {
  private config: Record<string, any>;

  constructor() {
    // Initialize with default configuration
    this.config = {
      // Server configuration
      server: {
        name: 'security-audit-server',
        version: '0.1.0',
      },
      
      // Tool configurations
      tools: {
        // Static analysis tools
        eslint: {
          enabled: true,
          dockerImage: 'node:16-alpine',
        },
        bandit: {
          enabled: true,
          dockerImage: 'python:3.9-alpine',
        },
        spotbugs: {
          enabled: true,
          dockerImage: 'openjdk:11-slim',
        },
        
        // Dynamic testing tools
        zap: {
          enabled: true,
          dockerImage: 'owasp/zap2docker-stable',
        },
        nuclei: {
          enabled: true,
          dockerImage: 'projectdiscovery/nuclei:latest',
        },
        
        // Dependency scanning tools
        dependencyCheck: {
          enabled: true,
          dockerImage: 'owasp/dependency-check',
        },
      },
      
      // Scan configurations
      scans: {
        static: {
          defaultDepth: 'standard',
          timeoutSeconds: 300,
        },
        dynamic: {
          defaultType: 'passive',
          timeoutSeconds: 600,
        },
        dependency: {
          timeoutSeconds: 300,
        },
        compliance: {
          timeoutSeconds: 300,
        },
      },
      
      // Report configurations
      reports: {
        defaultFormat: 'text',
        includeRecommendations: true,
      },
    };
    
    // Override with environment variables if available
    this.loadFromEnvironment();
  }

  /**
   * Load configuration from environment variables
   */
  private loadFromEnvironment() {
    // Server configuration
    if (process.env.SERVER_NAME) {
      this.config.server.name = process.env.SERVER_NAME;
    }
    if (process.env.SERVER_VERSION) {
      this.config.server.version = process.env.SERVER_VERSION;
    }
    
    // Tool configurations
    this.loadToolConfigFromEnv('ESLINT', 'eslint');
    this.loadToolConfigFromEnv('BANDIT', 'bandit');
    this.loadToolConfigFromEnv('SPOTBUGS', 'spotbugs');
    this.loadToolConfigFromEnv('ZAP', 'zap');
    this.loadToolConfigFromEnv('NUCLEI', 'nuclei');
    this.loadToolConfigFromEnv('DEPENDENCY_CHECK', 'dependencyCheck');
    
    // Scan configurations
    if (process.env.STATIC_SCAN_DEPTH) {
      this.config.scans.static.defaultDepth = process.env.STATIC_SCAN_DEPTH;
    }
    if (process.env.STATIC_SCAN_TIMEOUT) {
      this.config.scans.static.timeoutSeconds = parseInt(process.env.STATIC_SCAN_TIMEOUT, 10);
    }
    
    if (process.env.DYNAMIC_SCAN_TYPE) {
      this.config.scans.dynamic.defaultType = process.env.DYNAMIC_SCAN_TYPE;
    }
    if (process.env.DYNAMIC_SCAN_TIMEOUT) {
      this.config.scans.dynamic.timeoutSeconds = parseInt(process.env.DYNAMIC_SCAN_TIMEOUT, 10);
    }
    
    if (process.env.DEPENDENCY_SCAN_TIMEOUT) {
      this.config.scans.dependency.timeoutSeconds = parseInt(process.env.DEPENDENCY_SCAN_TIMEOUT, 10);
    }
    
    if (process.env.COMPLIANCE_SCAN_TIMEOUT) {
      this.config.scans.compliance.timeoutSeconds = parseInt(process.env.COMPLIANCE_SCAN_TIMEOUT, 10);
    }
    
    // Report configurations
    if (process.env.REPORT_DEFAULT_FORMAT) {
      this.config.reports.defaultFormat = process.env.REPORT_DEFAULT_FORMAT;
    }
    if (process.env.REPORT_INCLUDE_RECOMMENDATIONS) {
      this.config.reports.includeRecommendations = process.env.REPORT_INCLUDE_RECOMMENDATIONS === 'true';
    }
  }

  /**
   * Load tool configuration from environment variables
   * @param envPrefix The environment variable prefix
   * @param toolKey The tool key in the configuration
   */
  private loadToolConfigFromEnv(envPrefix: string, toolKey: string) {
    const enabledEnvVar = `${envPrefix}_ENABLED`;
    const imageEnvVar = `${envPrefix}_DOCKER_IMAGE`;
    
    if (process.env[enabledEnvVar]) {
      this.config.tools[toolKey].enabled = process.env[enabledEnvVar] === 'true';
    }
    
    if (process.env[imageEnvVar]) {
      this.config.tools[toolKey].dockerImage = process.env[imageEnvVar];
    }
  }

  /**
   * Get the server configuration
   * @returns The server configuration
   */
  getServerConfig() {
    return this.config.server;
  }

  /**
   * Get a tool configuration
   * @param tool The tool name
   * @returns The tool configuration
   */
  getToolConfig(tool: string) {
    return this.config.tools[tool];
  }

  /**
   * Get a scan configuration
   * @param scanType The scan type
   * @returns The scan configuration
   */
  getScanConfig(scanType: 'static' | 'dynamic' | 'dependency' | 'compliance') {
    return this.config.scans[scanType];
  }

  /**
   * Get the report configuration
   * @returns The report configuration
   */
  getReportConfig() {
    return this.config.reports;
  }

  /**
   * Check if a tool is enabled
   * @param tool The tool name
   * @returns Whether the tool is enabled
   */
  isToolEnabled(tool: string): boolean {
    return this.config.tools[tool]?.enabled || false;
  }

  /**
   * Get the Docker image for a tool
   * @param tool The tool name
   * @returns The Docker image
   */
  getToolDockerImage(tool: string): string {
    return this.config.tools[tool]?.dockerImage || '';
  }

  /**
   * Get the default scan depth for static analysis
   * @returns The default scan depth
   */
  getDefaultStaticScanDepth(): string {
    return this.config.scans.static.defaultDepth;
  }

  /**
   * Get the default scan type for dynamic testing
   * @returns The default scan type
   */
  getDefaultDynamicScanType(): string {
    return this.config.scans.dynamic.defaultType;
  }

  /**
   * Get the timeout for a scan type
   * @param scanType The scan type
   * @returns The timeout in seconds
   */
  getScanTimeout(scanType: 'static' | 'dynamic' | 'dependency' | 'compliance'): number {
    return this.config.scans[scanType].timeoutSeconds;
  }

  /**
   * Get the default report format
   * @returns The default report format
   */
  getDefaultReportFormat(): string {
    return this.config.reports.defaultFormat;
  }

  /**
   * Check if recommendations should be included in reports
   * @returns Whether recommendations should be included
   */
  shouldIncludeRecommendations(): boolean {
    return this.config.reports.includeRecommendations;
  }
}

// Export singleton instance
export const configUtil = new ConfigUtil();
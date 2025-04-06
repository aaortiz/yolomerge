import { dockerUtil } from '../utils/docker.js';
import { configUtil } from '../utils/config.js';
import * as url from 'url';

/**
 * Dynamic application security testing tool implementation
 */
export class DynamicTestingTool {
  /**
   * Perform dynamic security testing on a live application
   * @param targetUrl URL of the application to scan
   * @param scanType Type of scan to perform (passive or active)
   * @param includeApis Whether to include API endpoints in the scan
   * @returns The scan results
   */
  async scanLiveApplication(
    targetUrl: string,
    scanType: 'passive' | 'active' = 'passive',
    includeApis: boolean = false
  ): Promise<any> {
    console.error(`Starting dynamic security testing for ${targetUrl}`);
    console.error(`Scan type: ${scanType}`);
    console.error(`Include APIs: ${includeApis}`);
    
    // Validate the URL
    try {
      new URL(targetUrl);
    } catch (error) {
      throw new Error(`Invalid URL: ${targetUrl}`);
    }
    
    // Initialize results
    const results: any = {
      scan_id: `live-${Date.now()}`,
      scan_type: 'dynamic_testing',
      timestamp: new Date().toISOString(),
      target_url: targetUrl,
      scan_mode: scanType,
      include_apis: includeApis,
      vulnerabilities: [],
    };
    
    // Perform the scan
    try {
      // Run ZAP scan
      if (configUtil.isToolEnabled('zap')) {
        const zapVulnerabilities = await this.runZapScan(targetUrl, scanType, includeApis);
        results.vulnerabilities.push(...zapVulnerabilities);
      }
      
      // Run Nuclei scan
      if (configUtil.isToolEnabled('nuclei')) {
        const nucleiVulnerabilities = await this.runNucleiScan(targetUrl, scanType);
        results.vulnerabilities.push(...nucleiVulnerabilities);
      }
    } catch (error) {
      console.error(`Error during dynamic testing:`, error);
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
    
    console.error(`Dynamic security testing completed with ${results.vulnerabilities_count} vulnerabilities found`);
    
    return results;
  }

  /**
   * Run OWASP ZAP scan
   * @param targetUrl URL of the application to scan
   * @param scanType Type of scan to perform
   * @param includeApis Whether to include API endpoints
   * @returns Array of vulnerabilities
   */
  private async runZapScan(
    targetUrl: string,
    scanType: 'passive' | 'active',
    includeApis: boolean
  ): Promise<any[]> {
    console.error(`Running ZAP scan on ${targetUrl}`);
    
    try {
      // In a real implementation, this would run OWASP ZAP
      // For now, we'll simulate the scan with mock results
      
      // Simulate scan time based on scan type
      const scanTime = scanType === 'active' ? 2000 : 1000;
      await new Promise(resolve => setTimeout(resolve, Math.random() * scanTime));
      
      // Parse the URL to get the hostname and path
      const parsedUrl = new URL(targetUrl);
      const hostname = parsedUrl.hostname;
      const path = parsedUrl.pathname;
      
      // For demo purposes, return mock vulnerabilities
      const vulnerabilities = [
        {
          id: `zap-vuln-${Date.now()}-1`,
          type: 'cross_site_request_forgery',
          severity: 'high',
          endpoint: `${path}/api/user/update`,
          description: 'No CSRF token validation on state-changing operation',
          recommendation_id: 'rec-csrf-1',
        },
        {
          id: `zap-vuln-${Date.now()}-2`,
          type: 'missing_security_headers',
          severity: 'medium',
          endpoint: `${path}/*`,
          description: 'Content-Security-Policy header is not set',
          recommendation_id: 'rec-header-1',
        },
        {
          id: `zap-vuln-${Date.now()}-3`,
          type: 'information_disclosure',
          severity: 'medium',
          endpoint: `${path}/api/error`,
          description: 'Detailed error messages expose stack traces',
          recommendation_id: 'rec-info-1',
        },
      ];
      
      // Add more vulnerabilities for active scans
      if (scanType === 'active') {
        vulnerabilities.push({
          id: `zap-vuln-${Date.now()}-4`,
          type: 'cross_site_scripting',
          severity: 'high',
          endpoint: `${path}/search`,
          description: 'Reflected XSS vulnerability in search parameter',
          recommendation_id: 'rec-xss-1',
        });
        
        vulnerabilities.push({
          id: `zap-vuln-${Date.now()}-5`,
          type: 'sql_injection',
          severity: 'critical',
          endpoint: `${path}/products`,
          description: 'SQL injection vulnerability in product ID parameter',
          recommendation_id: 'rec-sqli-1',
        });
      }
      
      // Add API-specific vulnerabilities if requested
      if (includeApis) {
        vulnerabilities.push({
          id: `zap-vuln-${Date.now()}-6`,
          type: 'insecure_api_endpoint',
          severity: 'high',
          endpoint: `${path}/api/data`,
          description: 'API endpoint returns sensitive data without proper authentication',
          recommendation_id: 'rec-api-1',
        });
      }
      
      return vulnerabilities;
    } catch (error) {
      console.error('Error running ZAP scan:', error);
      return [];
    }
  }

  /**
   * Run Nuclei scan
   * @param targetUrl URL of the application to scan
   * @param scanType Type of scan to perform
   * @returns Array of vulnerabilities
   */
  private async runNucleiScan(
    targetUrl: string,
    scanType: 'passive' | 'active'
  ): Promise<any[]> {
    console.error(`Running Nuclei scan on ${targetUrl}`);
    
    try {
      // In a real implementation, this would run Nuclei
      // For now, we'll simulate the scan with mock results
      
      // Simulate scan time
      await new Promise(resolve => setTimeout(resolve, Math.random() * 1000));
      
      // Parse the URL to get the hostname and path
      const parsedUrl = new URL(targetUrl);
      const hostname = parsedUrl.hostname;
      const path = parsedUrl.pathname;
      
      // For demo purposes, return mock vulnerabilities
      const vulnerabilities = [
        {
          id: `nuclei-vuln-${Date.now()}-1`,
          type: 'open_redirect',
          severity: 'medium',
          endpoint: `${path}/redirect`,
          description: 'Open redirect vulnerability in redirect parameter',
          recommendation_id: 'rec-redirect-1',
        },
        {
          id: `nuclei-vuln-${Date.now()}-2`,
          type: 'cors_misconfiguration',
          severity: 'low',
          endpoint: `${path}/api/*`,
          description: 'CORS misconfiguration allows requests from any origin',
          recommendation_id: 'rec-cors-1',
        },
      ];
      
      // Add more vulnerabilities for active scans
      if (scanType === 'active') {
        vulnerabilities.push({
          id: `nuclei-vuln-${Date.now()}-3`,
          type: 'server_side_request_forgery',
          severity: 'high',
          endpoint: `${path}/proxy`,
          description: 'SSRF vulnerability in proxy endpoint',
          recommendation_id: 'rec-ssrf-1',
        });
      }
      
      return vulnerabilities;
    } catch (error) {
      console.error('Error running Nuclei scan:', error);
      return [];
    }
  }
}

// Export singleton instance
export const dynamicTestingTool = new DynamicTestingTool();
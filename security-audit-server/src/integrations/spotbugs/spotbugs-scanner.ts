import { dockerUtil } from '../../utils/docker.js';
import { configUtil } from '../../utils/config.js';
import * as fs from 'fs';
import * as path from 'path';
import * as xml2js from 'xml2js';

/**
 * SpotBugs security scanner for Java code
 */
export class SpotbugsScanner {
  /**
   * Run SpotBugs security scan on Java code
   * @param codePath Path to the code to scan (should contain compiled .class files)
   * @param scanDepth Depth of the scan (quick, standard, deep)
   * @returns Array of vulnerabilities found
   */
  async scanCode(
    codePath: string,
    scanDepth: 'quick' | 'standard' | 'deep' = 'standard'
  ): Promise<any[]> {
    console.error(`Running SpotBugs security scan on ${codePath}`);
    
    try {
      // Check if SpotBugs is enabled in the configuration
      if (!configUtil.isToolEnabled('spotbugs')) {
        console.error('SpotBugs scanning is disabled in configuration');
        return [];
      }
      
      // Get the Docker image from configuration
      const dockerImage = configUtil.getToolDockerImage('spotbugs') || 'openjdk:11-slim';
      
      // Determine the scan options based on the scan depth
      const scanOptions = this.getScanOptions(scanDepth);
      
      // Run SpotBugs in a Docker container
      const output = await this.runSpotbugsInDocker(dockerImage, codePath, scanOptions);
      
      // Parse the SpotBugs XML output and convert to vulnerabilities
      return await this.parseSpotbugsOutput(output, codePath);
    } catch (error) {
      console.error('Error running SpotBugs security scan:', error);
      throw error;
    }
  }
  
  /**
   * Get scan options based on scan depth
   * @param scanDepth Depth of the scan
   * @returns Scan options
   */
  private getScanOptions(scanDepth: 'quick' | 'standard' | 'deep'): string[] {
    const options: string[] = [];
    
    switch (scanDepth) {
      case 'quick':
        // Quick scan: low effort
        options.push('-effort:min');
        break;
      case 'deep':
        // Deep scan: max effort
        options.push('-effort:max');
        break;
      case 'standard':
      default:
        // Standard scan: default effort
        options.push('-effort:default');
        break;
    }
    
    return options;
  }
  
  /**
   * Run SpotBugs in a Docker container
   * @param dockerImage Docker image to use
   * @param codePath Path to the code to scan
   * @param options SpotBugs options
   * @returns SpotBugs XML output
   */
  private async runSpotbugsInDocker(
    dockerImage: string,
    codePath: string,
    options: string[]
  ): Promise<string> {
    // Create the SpotBugs command
    const spotbugsCommand = [
      'sh', '-c',
      `apt-get update && apt-get install -y wget unzip && ` +
      `wget https://github.com/spotbugs/spotbugs/releases/download/4.7.3/spotbugs-4.7.3.zip && ` +
      `unzip spotbugs-4.7.3.zip && ` +
      `wget https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-1.12.0/findsecbugs-plugin-1.12.0.jar -P spotbugs-4.7.3/plugin/ && ` +
      `spotbugs-4.7.3/bin/spotbugs -textui -xml:withMessages -output /tmp/report.xml ${options.join(' ')} -pluginList spotbugs-4.7.3/plugin/findsecbugs-plugin-1.12.0.jar -include /tmp/findsecbugs-include.xml -sourcepath /src /src`
    ];
    
    // Create Find Security Bugs include filter
    const includeFilter = `
      <FindBugsFilter>
        <Match>
          <Bug category="SECURITY"/>
        </Match>
      </FindBugsFilter>
    `;
    
    // Write include filter to a temporary file
    const filterPath = '/tmp/findsecbugs-include.xml';
    fs.writeFileSync(filterPath, includeFilter);
    
    // Set up volume bindings
    const binds = [
      `${codePath}:/src:ro`,
      `${filterPath}:/tmp/findsecbugs-include.xml:ro`,
    ];
    
    // Run SpotBugs in Docker
    await dockerUtil.runContainer(dockerImage, spotbugsCommand, binds);
    
    // Read the generated report
    const reportPath = '/tmp/report.xml';
    if (fs.existsSync(reportPath)) {
      const reportContent = fs.readFileSync(reportPath, 'utf-8');
      fs.unlinkSync(reportPath); // Clean up the report file
      fs.unlinkSync(filterPath); // Clean up the filter file
      return reportContent;
    } else {
      throw new Error('SpotBugs report file not found');
    }
  }
  
  /**
   * Parse SpotBugs XML output and convert to vulnerabilities
   * @param xmlOutput SpotBugs XML output
   * @param codePath Path to the code that was scanned
   * @returns Array of vulnerabilities
   */
  private async parseSpotbugsOutput(xmlOutput: string, codePath: string): Promise<any[]> {
    try {
      // Parse the XML output
      const parser = new xml2js.Parser();
      const spotbugsResults = await parser.parseStringPromise(xmlOutput);
      
      // Convert SpotBugs results to vulnerabilities
      const vulnerabilities: any[] = [];
      
      // Check if BugInstance exists
      if (spotbugsResults.BugCollection && spotbugsResults.BugCollection.BugInstance) {
        // Process each bug instance
        for (const bugInstance of spotbugsResults.BugCollection.BugInstance) {
          // Map SpotBugs priority to vulnerability severity
          const severity = this.mapSeverity(bugInstance.$.priority);
          
          // Create a unique ID for the vulnerability
          const id = `spotbugs-${Date.now()}-${vulnerabilities.length + 1}`;
          
          // Get location information
          let location = '';
          if (bugInstance.SourceLine && bugInstance.SourceLine[0]) {
            const sourceLine = bugInstance.SourceLine[0];
            const filename = sourceLine.$.sourcepath.replace('/src/', '');
            location = `${filename}:${sourceLine.$.start}`;
          }
          
          // Create the vulnerability object
          vulnerabilities.push({
            id,
            type: bugInstance.$.type,
            severity,
            location,
            description: bugInstance.LongMessage[0],
            recommendation_id: this.getRecommendationId(bugInstance.$.type),
            rule_id: bugInstance.$.type,
          });
        }
      }
      
      return vulnerabilities;
    } catch (error) {
      console.error('Error parsing SpotBugs output:', error);
      console.error('Raw output:', xmlOutput);
      return [];
    }
  }
  
  /**
   * Map SpotBugs priority to vulnerability severity
   * @param spotbugsPriority SpotBugs priority (1 = High, 2 = Medium, 3 = Low)
   * @returns Vulnerability severity
   */
  private mapSeverity(spotbugsPriority: string): string {
    switch (parseInt(spotbugsPriority, 10)) {
      case 1:
        return 'high';
      case 2:
        return 'medium';
      case 3:
        return 'low';
      default:
        return 'low';
    }
  }
  
  /**
   * Get recommendation ID for a vulnerability type
   * @param vulnType Vulnerability type (SpotBugs bug type)
   * @returns Recommendation ID
   */
  private getRecommendationId(vulnType: string): string {
    // Map SpotBugs bug types to recommendation IDs
    // This mapping would need to be more comprehensive in a real implementation
    const recommendationMap: Record<string, string> = {
      'COMMAND_INJECTION': 'rec-command-injection-1',
      'PATH_TRAVERSAL_IN': 'rec-path-traversal-1',
      'SQL_INJECTION': 'rec-sqli-1',
      'XSS_SERVLET': 'rec-xss-1',
      'XXE_DTD_PROCESSING': 'rec-xxe-1',
      'WEAK_HASHING': 'rec-crypto-1',
      'HARDCODED_CREDENTIALS': 'rec-cred-1',
      'INSECURE_RANDOM': 'rec-random-1',
    };
    
    return recommendationMap[vulnType] || 'rec-security-1';
  }
}

// Export singleton instance
export const spotbugsScanner = new SpotbugsScanner();
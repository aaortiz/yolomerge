import Dockerode from 'dockerode';

/**
 * Docker utility class for running security tools in containers
 */
export class DockerUtil {
  private docker: Dockerode;

  constructor() {
    // Initialize Docker client
    this.docker = new Dockerode();
  }

  /**
   * Pull a Docker image
   * @param image The image to pull (e.g., 'owasp/zap2docker-stable')
   */
  async pullImage(image: string): Promise<void> {
    console.error(`Pulling Docker image: ${image}`);
    
    return new Promise((resolve, reject) => {
      this.docker.pull(image, (err: any, stream: any) => {
        if (err) {
          console.error(`Error pulling image ${image}:`, err);
          return reject(err);
        }
        
        this.docker.modem.followProgress(stream, (err: any, output: any) => {
          if (err) {
            console.error(`Error following pull progress for ${image}:`, err);
            return reject(err);
          }
          
          console.error(`Successfully pulled image: ${image}`);
          resolve();
        });
      });
    });
  }

  /**
   * Run a command in a Docker container
   * @param image The image to use
   * @param cmd The command to run
   * @param binds Volume bindings
   * @param env Environment variables
   * @returns The command output
   */
  async runContainer(
    image: string,
    cmd: string[],
    binds: string[] = [],
    env: string[] = []
  ): Promise<string> {
    console.error(`Running container with image: ${image}`);
    console.error(`Command: ${cmd.join(' ')}`);
    
    // Check if image exists locally, pull if not
    try {
      await this.docker.getImage(image).inspect();
    } catch (error) {
      console.error(`Image ${image} not found locally, pulling...`);
      await this.pullImage(image);
    }
    
    // Create container
    const container = await this.docker.createContainer({
      Image: image,
      Cmd: cmd,
      HostConfig: {
        Binds: binds,
        AutoRemove: true,
      },
      Env: env,
      Tty: false,
    });
    
    // Start container
    await container.start();
    
    // Wait for container to finish
    await container.wait();
    
    // Get container logs
    const logs = await container.logs({
      stdout: true,
      stderr: true,
    });
    
    // Convert logs buffer to string
    const output = logs.toString('utf-8');
    
    console.error(`Container execution completed`);
    
    return output;
  }

  /**
   * Run OWASP ZAP scan
   * @param url The URL to scan
   * @param scanType The type of scan (passive or active)
   * @param includeApis Whether to include API endpoints
   * @returns The scan results
   */
  async runZapScan(
    url: string,
    scanType: 'passive' | 'active' = 'passive',
    includeApis: boolean = false
  ): Promise<string> {
    const image = 'owasp/zap2docker-stable';
    const cmd = [
      'zap-baseline.py',
      '-t', url,
      '-r', 'report.html',
      scanType === 'active' ? '-a' : '',
      includeApis ? '-j' : '',
    ].filter(Boolean);
    
    return this.runContainer(image, cmd);
  }

  /**
   * Run OWASP Dependency-Check scan
   * @param path The path to scan
   * @param packageManager The package manager type
   * @returns The scan results
   */
  async runDependencyCheck(
    path: string,
    packageManager?: 'npm' | 'pip' | 'maven'
  ): Promise<string> {
    const image = 'owasp/dependency-check';
    const cmd = [
      '--scan', '/src',
      '--format', 'JSON',
      '--out', '/report',
      '--enableExperimental',
    ];
    
    // Add package manager specific options
    if (packageManager) {
      switch (packageManager) {
        case 'npm':
          cmd.push('--enableNodeJS');
          break;
        case 'pip':
          cmd.push('--enablePython');
          break;
        case 'maven':
          cmd.push('--enableMaven');
          break;
      }
    }
    
    const binds = [
      `${path}:/src:ro`,
      '/tmp/dependency-check:/report',
    ];
    
    return this.runContainer(image, cmd, binds);
  }

  /**
   * Run ESLint security scan
   * @param path The path to scan
   * @returns The scan results
   */
  async runEslintScan(path: string): Promise<string> {
    const image = 'node:16-alpine';
    const cmd = [
      'sh', '-c',
      'npm install -g eslint @typescript-eslint/parser eslint-plugin-security && ' +
      'eslint --ext .js,.ts,.jsx,.tsx --plugin security --no-eslintrc -c /tmp/eslint-config.json /src'
    ];
    
    const eslintConfig = JSON.stringify({
      parser: '@typescript-eslint/parser',
      plugins: ['security'],
      extends: ['plugin:security/recommended'],
      rules: {
        'security/detect-buffer-noassert': 'error',
        'security/detect-child-process': 'error',
        'security/detect-disable-mustache-escape': 'error',
        'security/detect-eval-with-expression': 'error',
        'security/detect-no-csrf-before-method-override': 'error',
        'security/detect-non-literal-fs-filename': 'error',
        'security/detect-non-literal-regexp': 'error',
        'security/detect-non-literal-require': 'error',
        'security/detect-object-injection': 'error',
        'security/detect-possible-timing-attacks': 'error',
        'security/detect-pseudoRandomBytes': 'error',
        'security/detect-unsafe-regex': 'error'
      }
    });
    
    // Write ESLint config to a temporary file
    const fs = require('fs');
    const configPath = '/tmp/eslint-config.json';
    fs.writeFileSync(configPath, eslintConfig);
    
    const binds = [
      `${path}:/src:ro`,
      `${configPath}:/tmp/eslint-config.json:ro`,
    ];
    
    return this.runContainer(image, cmd, binds);
  }

  /**
   * Run Bandit security scan for Python
   * @param path The path to scan
   * @returns The scan results
   */
  async runBanditScan(path: string): Promise<string> {
    const image = 'python:3.9-alpine';
    const cmd = [
      'sh', '-c',
      'pip install bandit && bandit -r /src -f json'
    ];
    
    const binds = [
      `${path}:/src:ro`,
    ];
    
    return this.runContainer(image, cmd, binds);
  }

  /**
   * Run SpotBugs with Find Security Bugs for Java
   * @param path The path to scan
   * @returns The scan results
   */
  async runSpotBugsScan(path: string): Promise<string> {
    const image = 'openjdk:11-slim';
    const cmd = [
      'sh', '-c',
      'apt-get update && apt-get install -y wget unzip && ' +
      'wget https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-1.11.0/findsecbugs-cli-1.11.0.zip && ' +
      'unzip findsecbugs-cli-1.11.0.zip && ' +
      'chmod +x findsecbugs.sh && ' +
      './findsecbugs.sh -progress -html -output /tmp/report.html /src'
    ];
    
    const binds = [
      `${path}:/src:ro`,
    ];
    
    return this.runContainer(image, cmd, binds);
  }
}

// Export singleton instance
export const dockerUtil = new DockerUtil();
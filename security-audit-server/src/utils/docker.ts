import Dockerode from 'dockerode';
import * as fs from 'fs';

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
    console.error(`[DockerUtil] Attempting to run container with image: ${image}`);
    console.error(`[DockerUtil] Command: ${cmd.join(' ')}`);
    console.error(`[DockerUtil] Binds: ${binds.join(', ')}`);
    console.error(`[DockerUtil] Env: ${env.join(', ')}`);
    console.error(`[DockerUtil] Current working directory: ${process.cwd()}`);

    // Check if image exists locally, pull if not
    try {
      console.log(`[DockerUtil] Checking for local image: ${image}`);
      await this.docker.getImage(image).inspect();
      console.log(`[DockerUtil] Image ${image} found locally.`);
    } catch (error) {
      console.error(`[DockerUtil] Image ${image} not found locally or error inspecting: ${error}. Pulling image...`);
      try {
        await this.pullImage(image);
        console.log(`[DockerUtil] Successfully pulled image: ${image}`);
      } catch (pullError) {
         console.error(`[DockerUtil] FATAL: Failed to pull image ${image}: ${pullError}`);
         throw new Error(`Failed to pull Docker image ${image}: ${pullError}`);
      }
    }
    
    // Create container
    let container: Dockerode.Container;
    try {
      console.error(`[DockerUtil] Creating container...`);
      console.error(`[DockerUtil] Docker info: Attempting to create container with Docker`);
      
      const containerConfig = {
        Image: image,
        Cmd: cmd,
        HostConfig: {
          Binds: binds,
          AutoRemove: true, // Automatically remove container when stopped
        },
        Env: env,
        Tty: false, // Non-interactive
      };
      
      console.error(`[DockerUtil] Container config: ${JSON.stringify(containerConfig)}`);
      
      container = await this.docker.createContainer(containerConfig);
      console.error(`[DockerUtil] Container created successfully (ID: ${container.id}).`);
    } catch (createError) {
       console.error(`[DockerUtil] FATAL: Failed to create container for image ${image}: ${createError}`);
       throw new Error(`Failed to create Docker container: ${createError}`);
    }

    // Start container
    try {
       console.error(`[DockerUtil] Starting container (ID: ${container.id})...`);
       console.error(`[DockerUtil] Container ID: ${container.id}`);
       console.error(`[DockerUtil] Container image: ${image}`);
       console.error(`[DockerUtil] Container command: ${cmd.join(' ')}`);
       console.error(`[DockerUtil] Container binds: ${binds.join(', ')}`);
       
       await container.start();
       console.error(`[DockerUtil] Container started successfully.`);
    } catch (startError) {
       console.error(`[DockerUtil] FATAL: Failed to start container (ID: ${container.id}): ${startError}`);
       // Attempt to remove the container if start failed
       try { await container.remove({ force: true }); } catch (removeError) {}
       throw new Error(`Failed to start Docker container: ${startError}`);
    }
    
    // Wait for container to finish
    console.error(`[DockerUtil] Waiting for container (ID: ${container.id}) to complete...`);
    await container.wait(); // Wait for the container to stop
    console.error(`[DockerUtil] Container (ID: ${container.id}) finished.`);
    
    // Get container logs
    console.error(`[DockerUtil] Fetching logs for container (ID: ${container.id})...`);
    const logs = await container.logs({
      stdout: true, // Capture stdout
      stderr: true, // Capture stderr
    });
    console.error(`[DockerUtil] Logs fetched successfully.`);

    // Convert logs buffer to string
    // Dockerode logs often include an 8-byte header per chunk, need to handle this if raw stream is used.
    // The .toString() method here might be sufficient for simple cases.
    const output = Buffer.isBuffer(logs) ? logs.toString('utf-8') : String(logs); // Handle potential non-buffer logs
    
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
/**
 * Logger utility for the Security Audit MCP Server
 * 
 * This module provides a centralized logging mechanism for the security audit server.
 * It extends the existing console.error logging to file functionality with additional
 * logging levels and formatting.
 */

// Import the fs module for file operations
import * as fs from 'fs';
import * as path from 'path';

// Define log levels
export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  FATAL = 4
}

// Configuration for the logger
interface LoggerConfig {
  level: LogLevel;
  logToFile: boolean;
  logFilePath: string;
  logToConsole: boolean;
}

// Default configuration
const defaultConfig: LoggerConfig = {
  level: LogLevel.INFO,
  logToFile: true,
  logFilePath: './security-audit-server.log',
  logToConsole: true
};

// Current configuration
let config: LoggerConfig = { ...defaultConfig };

// Create log directory if it doesn't exist
const ensureLogDirectory = () => {
  if (config.logToFile) {
    const logDir = path.dirname(config.logFilePath);
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
  }
};

// Initialize the log file
const initLogFile = () => {
  if (config.logToFile) {
    ensureLogDirectory();
    // Append a header to the log file if it's new
    if (!fs.existsSync(config.logFilePath)) {
      fs.writeFileSync(
        config.logFilePath,
        `=== Security Audit MCP Server Log - Started at ${new Date().toISOString()} ===\n`
      );
    }
  }
};

// Format a log message
const formatLogMessage = (level: string, message: string): string => {
  return `[${new Date().toISOString()}] [${level}] ${message}`;
};

// Write to log file
const writeToLogFile = (message: string) => {
  if (config.logToFile) {
    try {
      fs.appendFileSync(config.logFilePath, message + '\n');
    } catch (error) {
      console.error(`Failed to write to log file: ${error}`);
    }
  }
};

// Configure the logger
export const configureLogger = (newConfig: Partial<LoggerConfig>) => {
  config = { ...config, ...newConfig };
  initLogFile();
};

// Log a message at a specific level
const log = (level: LogLevel, levelName: string, ...args: any[]) => {
  if (level >= config.level) {
    const message = args.map(arg => 
      typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
    ).join(' ');
    
    const formattedMessage = formatLogMessage(levelName, message);
    
    if (config.logToConsole) {
      if (level >= LogLevel.ERROR) {
        console.error(formattedMessage);
      } else if (level === LogLevel.WARN) {
        console.warn(formattedMessage);
      } else {
        console.log(formattedMessage);
      }
    }
    
    if (config.logToFile) {
      writeToLogFile(formattedMessage);
    }
  }
};

// Logger methods
export const logger = {
  debug: (...args: any[]) => log(LogLevel.DEBUG, 'DEBUG', ...args),
  info: (...args: any[]) => log(LogLevel.INFO, 'INFO', ...args),
  warn: (...args: any[]) => log(LogLevel.WARN, 'WARN', ...args),
  error: (...args: any[]) => log(LogLevel.ERROR, 'ERROR', ...args),
  fatal: (...args: any[]) => log(LogLevel.FATAL, 'FATAL', ...args),
  
  // Log method execution with timing
  logMethod: async <T>(
    methodName: string, 
    args: any, 
    method: () => Promise<T>
  ): Promise<T> => {
    logger.info(`Starting ${methodName} with args:`, args);
    const startTime = Date.now();
    
    try {
      const result = await method();
      const duration = Date.now() - startTime;
      logger.info(`Completed ${methodName} in ${duration}ms`);
      return result;
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error(`Failed ${methodName} after ${duration}ms:`, error);
      throw error;
    }
  }
};

// Initialize the logger
initLogFile();

export default logger;
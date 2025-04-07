/**
 * Custom ESLint security rules to detect common security vulnerabilities
 */

module.exports = {
  rules: {
    // Detect command injection vulnerabilities
    'detect-command-injection': {
      create: function(context) {
        return {
          CallExpression(node) {
            // Check for child_process.exec, execSync, spawn, etc.
            if (
              // Direct exec call
              (node.callee.name === 'exec') ||
              // child_process.exec, etc.
              (node.callee.type === 'MemberExpression' &&
                ((node.callee.object.name === 'exec') ||
                (node.callee.object.type === 'Identifier' &&
                  (node.callee.object.name === 'child_process' ||
                   node.callee.object.name === 'cp') &&
                  (node.callee.property.name === 'exec' ||
                   node.callee.property.name === 'execSync' ||
                   node.callee.property.name === 'spawn' ||
                   node.callee.property.name === 'spawnSync'))))
            ) {
              // Check if the command includes concatenation, template literals, or any non-literal
              if (node.arguments.length > 0) {
                const arg = node.arguments[0];
                if (arg.type !== 'Literal') {
                  context.report({
                    node,
                    message: 'Potential command injection vulnerability detected. User input should not be used in command execution.'
                  });
                }
              }
            }
          }
        };
      }
    },
    
    // Detect path traversal vulnerabilities
    'detect-path-traversal': {
      create: function(context) {
        return {
          CallExpression(node) {
            // Check for fs.readFile, readFileSync, writeFile, etc.
            if (
              // Direct fs method calls
              (node.callee.type === 'MemberExpression' &&
               node.callee.object.name === 'fs' &&
               (node.callee.property.name === 'readFile' ||
                node.callee.property.name === 'readFileSync' ||
                node.callee.property.name === 'writeFile' ||
                node.callee.property.name === 'writeFileSync' ||
                node.callee.property.name === 'appendFile' ||
                node.callee.property.name === 'appendFileSync' ||
                node.callee.property.name === 'open' ||
                node.callee.property.name === 'openSync'))
            ) {
              // Check if the path is a variable (not a literal)
              if (node.arguments.length > 0 && node.arguments[0].type !== 'Literal') {
                context.report({
                  node,
                  message: 'Potential path traversal vulnerability detected. File paths should be validated before use.'
                });
              }
            }
          }
        };
      }
    },
    
    // Detect regex DoS vulnerabilities
    'detect-regex-dos': {
      create: function(context) {
        // Patterns that can lead to ReDoS
        const dangerousPatterns = [
          /\(\.\*\)\+/,  // (.*)+
          /\(\[^\]\*\)\+/,  // ([^])+
          /\(\.\+\)\+/,  // (.+)+
          /\(a\+\)\+/,   // (a+)+
          /\\\.\*\\\.\*/,  // \..*\..*
          /\(\?:<[^>]+>\)\+/,  // (?:<...>)+
          /\([^)]+\)\+\+/,  // (x)+
          /\([^)]+\+\)\+/   // (x+)+
        ];
        
        return {
          Literal(node) {
            // Check regex literals
            if (node.regex) {
              const pattern = node.regex.pattern;
              for (const dangerousPattern of dangerousPatterns) {
                if (dangerousPattern.test(pattern)) {
                  context.report({
                    node,
                    message: 'Potential regex DoS (ReDoS) vulnerability detected. Avoid nested repetition quantifiers.'
                  });
                  break;
                }
              }
            }
          },
          
          NewExpression(node) {
            // Check new RegExp()
            if (node.callee.name === 'RegExp' && node.arguments.length > 0) {
              // Handle both string literals and variables
              if (node.arguments[0].type === 'Literal' && typeof node.arguments[0].value === 'string') {
                const pattern = node.arguments[0].value;
                for (const dangerousPattern of dangerousPatterns) {
                  if (dangerousPattern.test(pattern)) {
                    context.report({
                      node,
                      message: 'Potential regex DoS (ReDoS) vulnerability detected. Avoid nested repetition quantifiers.'
                    });
                    break;
                  }
                }
              } else {
                // If the pattern is not a literal (e.g., a variable), report it as potentially unsafe
                context.report({
                  node,
                  message: 'Potential regex DoS (ReDoS) vulnerability detected. Regex patterns from variables should be validated.'
                });
              }
            }
          }
        };
      }
    },
    
    // Detect code injection vulnerabilities (beyond eval)
    'detect-code-injection': {
      create: function(context) {
        return {
          CallExpression(node) {
            // Check for eval, Function constructor, setTimeout/setInterval with string arg
            if (
              // Direct eval call
              (node.callee.name === 'eval') ||
              // setTimeout, setInterval with string first arg
              ((node.callee.name === 'setTimeout' || node.callee.name === 'setInterval') &&
               node.arguments.length > 0 &&
               node.arguments[0].type === 'Literal' &&
               typeof node.arguments[0].value === 'string')
            ) {
              context.report({
                node,
                message: 'Potential code injection vulnerability detected. Avoid using eval or passing strings to setTimeout/setInterval.'
              });
            }
          },
          
          NewExpression(node) {
            // Check for new Function()
            if (node.callee.name === 'Function') {
              context.report({
                node,
                message: 'Potential code injection vulnerability detected. Avoid using the Function constructor.'
              });
            }
          }
        };
      }
    }
  }
};
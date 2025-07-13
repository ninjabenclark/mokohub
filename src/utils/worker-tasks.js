/**
 * src/utils/worker-tasks.js
 *
 * Contains CPU-intensive logic extracted from AutoSummarizePlugin for execution in worker threads.
 * All functions here are pure and accept necessary configurations and data as arguments.
 */

'use strict';

const crypto = require('crypto');
const fallbackDiffParser = require('./fallback-diff-parser'); // Ensure this path is correct relative to worker-tasks.js

/**
 * Helper function to determine if a change line is significant enough to highlight.
 * This is a direct copy from AutoSummarizePlugin's isSignificantChange.
 * @param {string} content - line content
 * @returns {boolean} whether change is significant
 */
function isSignificantChange(content) {
    const trimmed = content.trim();

    if (trimmed.length < 5 && !(/[a-zA-Z0-9]/.test(trimmed))) return false;
    if (/^[\s\{\}\[\]\(\);,:"'`]*$/.test(trimmed)) return false;
    if (/^\s*(\/\/|\/\*|<!--|#|\*)/.test(trimmed)) return false;
    if (trimmed.endsWith(';') || trimmed.endsWith(',')) {
        if (trimmed.length < 10 && !trimmed.includes('=')) return false;
    }
    if (/^('|").*\1$/.test(trimmed) && trimmed.length < 50) {
        return false;
    }

    const importantPatterns = [
        /function\s+\w+/i, /class\s+\w+/i, /interface\s+\w+/i,
        /import\s+.*from/i, /export\s+(default\s+)?/i,
        /(const|let|var)\s+\w+\s*=/i,
        /if\s*\(.+\)/i, /else\s*(if\s*\(.+\))?/,
        /for\s*\(.+\)/i, /while\s*\(.+\)/i,
        /return\s+/, /throw\s+/, /try\s*\{/, /catch\s*\(.+\)/,
        /async\s+(function\s+)?/i, /await\s+/,
        /^\s*(public|private|protected)\s+(static\s+)?(async\s+)?(function|const|var|let)?/i,
        /^(fetch|axios|http)\./i,
        /\.(map|filter|reduce|forEach|find|sort)\(/i,
        /(new\s+\w+)/i,
        /(console\.(log|warn|error|debug))/i
    ];

    return importantPatterns.some(pattern => pattern.test(trimmed));
}

/**
 * Helper function: extracts a small snippet of the line content around the detected keyword for context.
 * Direct copy from AutoSummarizePlugin's extractContext.
 */
function extractContext(originalContent, keyword, buffer = 30) {
    const lowerContent = originalContent.toLowerCase();
    const lowerKeyword = keyword.toLowerCase();
    const keywordIndex = lowerContent.indexOf(lowerKeyword);

    if (keywordIndex === -1) {
        return originalContent.substring(0, Math.min(originalContent.length, 100)) + (originalContent.length > 100 ? '...' : '');
    }

    const start = Math.max(0, keywordIndex - buffer);
    const end = Math.min(originalContent.length, keywordIndex + lowerKeyword.length + buffer);

    let context = originalContent.substring(start, end);

    if (start > 0) context = '...' + context;
    if (end < originalContent.length) context = context + '...';

    return context;
}

/**
 * Helper function: Generates a specific recommendation for a general keyword-based security flag.
 * Direct copy from AutoSummarizePlugin's generateRecommendation.
 */
function generateRecommendation(keyword, lineContent, filePath) {
    const lowerKeyword = keyword.toLowerCase();
    if (['password', 'secret', 'token', 'key'].includes(lowerKeyword)) {
        return `Avoid hardcoding '${keyword}'. Use environment variables or a secure secrets management system.`;
    }
    if (['admin', 'auth', 'privilege', 'permission', 'role'].includes(lowerKeyword)) {
        return `Review access control logic involving '${keyword}'. Ensure principle of least privilege is applied.`;
    }
    if (['sql', 'injection', 'xss', 'csrf'].includes(lowerKeyword)) {
        return `Sanitize all user inputs and use parameterized queries or ORM frameworks to prevent '${keyword}'.`;
    }
    if (['eval', 'exec', 'shell'].includes(lowerKeyword)) {
        return `Avoid dynamic code execution like '${keyword}'. If necessary, validate inputs rigorously and use safer alternatives.`;
    }
    if (['encrypt', 'decrypt', 'hash'].includes(lowerKeyword)) {
        return `Verify correct cryptographic practices for '${keyword}'. Use strong, industry-standard algorithms and key management.`;
    }
    if (['personal', 'sensitive', 'private', 'confidential', 'pii', 'gdpr'].includes(lowerKeyword)) {
        return `Ensure proper handling and protection of '${keyword}' data. Verify compliance with data privacy regulations.`;
    }
    if (lowerKeyword === 'delete') {
        return `Review '${keyword}' operation for data integrity and authorization. Ensure no unintended data loss.`;
    }
    if (lowerKeyword === 'hardcode') {
        return `Avoid hardcoding values. Use configuration files, environment variables, or constants.`;
    }
    return `Investigate the usage of '${keyword}' in ${filePath}. Review for potential security implications or best practice violations.`;
}

/**
 * Helper function: Generates a specific recommendation for a pattern-based security flag.
 * Direct copy from AutoSummarizePlugin's generatePatternRecommendation.
 */
function generatePatternRecommendation(keyword, lineContent) {
    switch (keyword) {
        case 'hardcoded_secret':
            return `**CRITICAL: Hardcoded secret detected!** Remove immediately and use a secure secret management solution (e.g., environment variables, Vault).`;
        case 'code_injection':
            return `**HIGH: Potential code injection vulnerability!** Refactor to avoid dynamic code evaluation or ensure strict input validation and sanitization.`;
        case 'sql_injection':
            return `**HIGH: Potential SQL injection vulnerability!** Refactor queries to use parameterized statements or an ORM; never concatenate user input directly into SQL.`;
        case 'xss_vulnerability':
            return `**HIGH: Potential Cross-Site Scripting (XSS)!** Sanitize all user-supplied input before rendering in HTML. Consider Content Security Policy (CSP).`;
        default:
            return `A suspicious pattern ('${keyword}') was detected. Review the line for potential security vulnerabilities.`;
    }
}

/**
 * Helper function: Analyzes the overall PR context for security relevance.
 * Direct copy from AutoSummarizePlugin's analyzeSecurityContext.
 */
function analyzeSecurityContext(prData, config) {
    let contextScore = 0;
    const contextKeywords = new Set();
    const lowRiskKeywords = ['docs', 'refactor', 'style', 'chore', 'test', 'typo'];

    const prContent = `${prData.title || ''} ${prData.description || ''}`.toLowerCase();
    for (const keyword of config.flagKeywords) {
        if (prContent.includes(keyword)) {
            contextScore += (config.riskWeights[keyword] || 3) * 0.5;
            contextKeywords.add(keyword);
        }
    }

    if (Array.isArray(prData.labels)) {
        for (const label of prData.labels) {
            const lowerLabel = label.toLowerCase();
            if (config.flagKeywords.some(kw => lowerLabel.includes(kw))) {
                contextScore += 2;
                contextKeywords.add(lowerLabel);
            }
            if (lowRiskKeywords.includes(lowerLabel)) {
                contextScore = Math.max(0, contextScore - 1);
            }
        }
    }
    return {
        score: Math.min(contextScore, 10),
        keywords: Array.from(contextKeywords)
    };
}

/**
 * Helper function: Calculates a risk multiplier based on the file path.
 * Direct copy from AutoSummarizePlugin's calculateFileRiskMultiplier.
 */
function calculateFileRiskMultiplier(filePath) {
    const lowerFilePath = filePath.toLowerCase();
    let multiplier = 1.0;

    const highRiskPatterns = [
        /^(src\/)?(auth|security|db|database|config|keys|secrets)\//,
        /\.(env|pem|key)$/,
        /package\.json$/,
        /dockerfile$/
    ];

    const mediumRiskPatterns = [
        /^(src\/)?(api|middleware|controllers|services)\//,
        /\.(sql|graphql)$/,
        /\.config\.(js|ts|json)$/,
        /\.yaml$|\.yml$/
    ];

    if (highRiskPatterns.some(p => p.test(lowerFilePath))) {
        multiplier = Math.max(multiplier, 2.0);
    } else if (mediumRiskPatterns.some(p => p.test(lowerFilePath))) {
        multiplier = Math.max(multiplier, 1.5);
    }
    return multiplier;
}

/**
 * Helper function: Calculates a context-specific weight for a security flag keyword within a line.
 * Direct copy from AutoSummarizePlugin's calculateContextWeight.
 */
function calculateContextWeight(keyword, originalContent) {
    const lowerContent = originalContent.toLowerCase();
    let weight = 1.0;

    if (lowerContent.startsWith('//') || lowerContent.startsWith('/*') || lowerContent.includes('TODO:') || lowerContent.includes('FIXME:')) {
        return 0.1;
    }
    if (lowerContent.includes(`"${keyword}"`) || lowerContent.includes(`'${keyword}'`)) {
        weight *= 0.5;
    }

    if (/(const|let|var)\s+\w*\s*=\s*\w*password|token|secret/i.test(originalContent) ||
        /(authenticate|authorize|encrypt|decrypt|hash|decode|admin|root)\s*\(.*\)/i.test(originalContent) ||
        /SELECT\s+.*FROM\s+.*WHERE/i.test(originalContent)
    ) {
        weight *= 1.5;
    }

    switch (keyword) {
        case 'eval': case 'exec': case 'shell': case 'injection': case 'vulnerability': case 'exploit':
            weight *= 2.0; break;
        case 'delete':
            if (!/(user|account|record|db|database|file|entry)/i.test(originalContent)) {
                weight *= 0.2;
            }
            break;
    }
    return Math.min(weight, 3.0);
}

/**
 * Helper function: Combines base risk weight, file risk multiplier, context weight, and PR context score
 * to calculate a final severity level and numeric risk score for a single flag.
 * Direct copy from AutoSummarizePlugin's calculateSeverity.
 */
function calculateSeverity(baseWeight, fileRiskMultiplier, contextWeight, contextAnalysis) {
    let rawScore = baseWeight * fileRiskMultiplier * contextWeight;
    rawScore += contextAnalysis.score * 0.2;

    const normalizedScore = Math.min(rawScore / 5, 10);

    let level;
    if (normalizedScore >= 9) { level = 'critical'; }
    else if (normalizedScore >= 7) { level = 'high'; }
    else if (normalizedScore >= 4) { level = 'medium'; }
    else { level = 'low'; }

    return { level: level, score: parseFloat(normalizedScore.toFixed(1)) };
}

/**
 * Helper function: Consolidates, deduplicates, and sorts security flags.
 * Direct copy from AutoSummarizePlugin's consolidateFlags.
 */
function consolidateFlags(flags) {
    if (!Array.isArray(flags) || flags.length === 0) {
        return [];
    }

    const uniqueFlags = new Map();
    for (const flag of flags) {
        const uniqueKey = `${flag.file}|${flag.keyword}|${flag.type}|${crypto.createHash('sha1').update(flag.line || '').digest('hex')}`;
        if (!uniqueFlags.has(uniqueKey)) {
            uniqueFlags.set(uniqueKey, flag);
        } else {
            const existingFlag = uniqueFlags.get(uniqueKey);
            if (flag.riskScore > existingFlag.riskScore) {
                uniqueFlags.set(uniqueKey, flag);
            }
        }
    }

    let consolidated = Array.from(uniqueFlags.values());
    const severityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };
    consolidated.sort((a, b) => {
        const orderA = severityOrder[a.severity] || 0;
        const orderB = severityOrder[b.severity] || 0;
        if (orderA !== orderB) { return orderB - orderA; }
        return b.riskScore - a.riskScore;
    });
    return consolidated;
}


/**
 * Worker-executable function for processing a single file diff.
 * @param {Object} data - Contains file object and config.
 * @returns {Object} Processed file data (fileChange, keyChanges).
 */
async function processFileWorker({ file, config }) {
    const fileChange = {
        filePath: file.filePath,
        adds: 0,
        dels: 0,
        modifies: 0
    };
    const keyChanges = [];

    for (const hunk of file.hunks || []) {
        for (const line of hunk.lines || []) {
            if (line.type === 'add') {
                fileChange.adds++;
                if (isSignificantChange(line.content)) {
                    keyChanges.push(`➕ ${file.filePath}: ${line.content.trim().substring(0, 80)}`);
                }
            } else if (line.type === 'del') {
                fileChange.dels++;
                if (isSignificantChange(line.content)) {
                    keyChanges.push(`➖ ${file.filePath}: ${line.content.trim().substring(0, 80)}`);
                }
            }
        }
    }
    return { fileChange, keyChanges: keyChanges.slice(0, 5) }; // Limit per file
}

/**
 * Worker-executable function for manual diff parsing.
 * @param {Object} data - Contains diffContent.
 * @returns {Object} Manually parsed diff.
 */
function manualDiffParseWorker({ diffContent }) {
    const lines = diffContent.split('\n');
    const files = [];
    let currentFile = null;
    let currentHunk = null;

    const extractFilePath = (line) => {
        const match = line.match(/--- a\/(.*)|--- \/dev\/null/);
        return match ? match[1] || '/dev/null' : 'unknown';
    };

    for (const line of lines) {
        if (line.startsWith('--- ')) {
            if (currentFile) files.push(currentFile);
            currentFile = {
                filePath: extractFilePath(line),
                hunks: []
            };
        } else if (line.startsWith('@@ ')) {
            if (currentFile) {
                currentHunk = { lines: [] };
                currentFile.hunks.push(currentHunk);
            }
        } else if (currentHunk && (line.startsWith('+') || line.startsWith('-') || line.startsWith(' '))) {
            const type = line.startsWith('+') ? 'add' :
                         line.startsWith('-') ? 'del' : 'context';
            currentHunk.lines.push({
                type,
                content: line.substring(1)
            });
        }
    }
    if (currentFile) files.push(currentFile);
    return { files };
}

/**
 * Worker-executable function for security flag detection.
 * @param {Object} data - Contains parsedDiff, prData, and config.
 * @returns {Array} Security flags with risk scores.
 */
async function detectSecurityFlagsWorker({ parsedDiff, prData, config }) {
    const flags = [];
    const contextAnalysis = analyzeSecurityContext(prData, config);

    for (const file of parsedDiff.files || []) {
        const fileRiskMultiplier = calculateFileRiskMultiplier(file.filePath);

        for (const hunk of file.hunks || []) {
            for (const line of hunk.lines || []) {
                if (line.type === 'add' || line.type === 'del') {
                    const lineFlags = await analyzeLineWorker(
                        line,
                        file.filePath,
                        fileRiskMultiplier,
                        contextAnalysis,
                        config
                    );
                    flags.push(...lineFlags);
                }
            }
        }
    }
    return consolidateFlags(flags);
}

/**
 * Helper function for advanced line analysis for security patterns (used by detectSecurityFlagsWorker).
 * Direct copy from AutoSummarizePlugin's analyzeLine.
 */
async function analyzeLineWorker(line, filePath, fileRiskMultiplier, contextAnalysis, config) {
    const flags = [];
    const content = line.content.toLowerCase();
    const originalContent = line.content;

    for (const keyword of config.flagKeywords) {
        if (content.includes(keyword)) {
            const baseWeight = config.riskWeights[keyword] || 3;
            const contextWeight = calculateContextWeight(keyword, originalContent);
            const severity = calculateSeverity(
                baseWeight,
                fileRiskMultiplier,
                contextWeight,
                contextAnalysis
            );

            flags.push({
                file: filePath,
                keyword,
                line: originalContent,
                lineNumber: line.ln || line.ln1 || line.ln2,
                type: line.type,
                severity: severity.level,
                riskScore: severity.score,
                context: extractContext(originalContent, keyword),
                recommendation: generateRecommendation(keyword, originalContent, filePath)
            });
        }
    }

    const patterns = [
        {
            pattern: /(?:password|secret|token|key)\s*[=:]\s*['""][^'"]{8,}['"]/i,
            keyword: 'hardcoded_secret',
            severity: 'critical'
        },
        {
            pattern: /eval\s*\(\s*.*\$\{.*\}\s*\)/i,
            keyword: 'code_injection',
            severity: 'high'
        },
        {
            pattern: /SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\+.*['"]/i,
            keyword: 'sql_injection',
            severity: 'high'
        }
    ];

    for (const { pattern, keyword, severity } of patterns) {
        if (pattern.test(originalContent)) {
            flags.push({
                file: filePath,
                keyword,
                line: originalContent,
                lineNumber: line.ln || line.ln1 || line.ln2,
                type: line.type,
                severity,
                riskScore: severity === 'critical' ? 10 : severity === 'high' ? 8 : 6,
                context: 'Pattern-based detection',
                recommendation: generatePatternRecommendation(keyword, originalContent)
            });
        }
    }
    return flags;
}


module.exports = {
    processFileWorker,
    manualDiffParseWorker,
    detectSecurityFlagsWorker,
    // Exporting helpers if they might be useful for testing directly, though not strictly needed by worker.js
    isSignificantChange,
    extractContext,
    generateRecommendation,
    generatePatternRecommendation,
    analyzeSecurityContext,
    calculateFileRiskMultiplier,
    calculateContextWeight,
    calculateSeverity,
    consolidateFlags
};

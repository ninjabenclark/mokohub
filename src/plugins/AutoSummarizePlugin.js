/**
 * AutoSummarizePlugin.js
 *
 * Production-grade PR summarization for MokoHub GitHub Automation Suite.
 * Upgraded for async efficiency, robust diff parsing, and enhanced security detection.
 * Designed for both human developers and AI agents.
 *
 * Features:
 * - Async/parallel processing with batching (now using a hardened worker thread pool)
 * - Resilient diff parsing with fallback strategies
 * - Multi-layered security risk detection
 * - Context-aware summarization for humans vs agents
 * - Performance monitoring and error recovery
 * - Comprehensive archive system with cross-chat access
 *
 * @version 0.3.0
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const { Worker } = require('worker_threads');

// Primary diff parser (still used on main thread for first attempt)
const unifiedDiffParser = require('diffparser');

// Note: `fallbackDiffParser` is now only required within `src/utils/worker-tasks.js`
// if `manualDiffParseWorker` uses it. The main thread doesn't need it directly here.

class AutoSummarizePlugin {
    constructor(config = {}) {
        this.config = Object.assign({
            // Core settings
            maxSummaryLength: 600,
            collapseSimilarChanges: true,

            // Security detection (enhanced)
            flagKeywords: [
                'delete', 'admin', 'auth', 'password', 'token', 'secret', 'key',
                'payment', 'billing', 'credit', 'encrypt', 'decrypt', 'hash',
                'privilege', 'permission', 'role', 'sudo', 'root',
                'sql', 'injection', 'xss', 'csrf', 'eval', 'exec', 'shell',
                'vulnerability', 'exploit', 'backdoor', 'hardcode',
                'personal', 'sensitive', 'private', 'confidential', 'gdpr',
                'pii', 'database', 'backup', 'restore'
            ],

            // Risk scoring weights
            riskWeights: {
                'delete': 9, 'admin': 8, 'password': 8, 'token': 7, 'secret': 9,
                'payment': 9, 'sql': 8, 'injection': 9, 'xss': 7, 'eval': 8,
                'exec': 8, 'shell': 7, 'vulnerability': 9, 'exploit': 9,
                'hardcode': 6, 'private': 5, 'auth': 6, 'encrypt': 4
            },

            // Performance settings
            batchSize: 50,
            maxConcurrentWorkers: 4,
            // Global default timeout for worker tasks, can be overridden per task
            workerTaskTimeout: 30000,

            // Archive settings
            archiveEnabled: true,
            archivePath: './archives',
            projectId: config.projectId || 'default',
            maxArchiveEntries: 2000,
            enableCrossChat: true,

            // Summarization modes
            summaryMode: 'adaptive', // 'human', 'agent', 'adaptive'
            includeMetrics: true,
            includeContext: true,
        }, config);

        this.archiveManager = new ArchiveManager(this.config);
        this.performanceMetrics = new PerformanceTracker();
        this.diffParserCache = new Map();

        // Worker Pool Management
        this.workerPool = []; // Stores active worker instances
        this.workerQueue = []; // Stores pending tasks when workers are busy
        this.initializeWorkerPool();

        // Bind utility methods that might be used by external modules or tests
        this.hashSummary = this.hashSummary.bind(this);
        this.categorizeChangeSize = this.categorizeChangeSize.bind(this);
        this.categorizeRisk = this.categorizeRisk.bind(this);
        this.validateParsedDiff = this.validateParsedDiff.bind(this);
        this.extractFileList = this.extractFileList.bind(this);
        this.classifyFileChange = this.classifyFileChange.bind(this);
        this.detectOptimalMode = this.detectOptimalMode.bind(this);
        this.calculateMetrics = this.calculateMetrics.bind(this);
        this.calculateLineComplexity = this.calculateLineComplexity.bind(this);
        this.assessChangeScope = this.assessChangeScope.bind(this);
        this.assessChangeRisk = this.assessChangeRisk.bind(this);
        this.suggestTesting = this.suggestTesting.bind(this);
        this.batchFiles = this.batchFiles.bind(this);
        this.countTotalLines = this.countTotalLines.bind(this);
    }

    /**
     * Initializes the worker pool, creating Worker instances and setting up their listeners.
     * Each worker is managed with a busy state and robust error/exit handling.
     */
    initializeWorkerPool() {
        for (let i = 0; i < this.config.maxConcurrentWorkers; i++) {
            // Path to worker script should be absolute or relative to __dirname
            const worker = new Worker(path.resolve(__dirname, 'summarize-worker.js'));
            worker.isBusy = false; // Custom flag to track worker availability
            worker.id = `worker-${i}`; // Assign a unique ID for debugging

            worker.on('message', (message) => {
                const { task, result, error, stack } = message;
                // Find the specific task in the queue that this message resolves
                // Need to find by task AND worker, as multiple tasks for the same 'task' type can be queued
                const resolverIndex = this.workerQueue.findIndex(q => q.task === task && q.worker === worker);

                if (resolverIndex !== -1) {
                    const taskEntry = this.workerQueue[resolverIndex];
                    // Clear the timeout associated with this specific task
                    if (taskEntry.timeoutId) {
                        clearTimeout(taskEntry.timeoutId);
                    }

                    if (error) {
                        const err = new Error(error);
                        err.stack = stack; // Preserve original stack trace from worker
                        resolver.reject(err);
                        console.error(`[AutoSummarizePlugin] Task '${task}' on worker ${worker.id} failed:`, error); // Log specific task failure
                    } else {
                        resolver.resolve(result);
                    }
                    // Mark worker as free and remove the resolved task from the queue
                    worker.isBusy = false;
                    this.workerQueue.splice(resolverIndex, 1);
                    this.processNextWorkerTask(); // Try to process next queued task
                } else {
                    console.warn(`[AutoSummarizePlugin] Received unexpected message from worker ${worker.id} for task '${task}'. It might have already timed out or been resolved.`);
                }
            });

            worker.on('error', (err) => {
                console.error(`[AutoSummarizePlugin] Worker ${worker.id} experienced an unhandled error: ${err.message}`, err.stack);
                // Reject any pending tasks assigned to this worker
                this.workerQueue.filter(q => q.worker === worker).forEach(q => {
                    if (q.timeoutId) clearTimeout(q.timeoutId); // Clear timeout for affected tasks
                    q.reject(err);
                });
                // Clean up tasks associated with this worker
                this.workerQueue = this.workerQueue.filter(q => q.worker !== worker);
                this.replaceWorker(worker); // Attempt to replace the failed worker
            });

            worker.on('exit', (code) => {
                if (code !== 0) {
                    console.error(`[AutoSummarizePlugin] Worker ${worker.id} exited unexpectedly with code ${code}.`);
                    // Reject pending tasks for this worker due to unexpected exit
                    this.workerQueue.filter(q => q.worker === worker).forEach(q => {
                        if (q.timeoutId) clearTimeout(q.timeoutId); // Clear timeout for affected tasks
                        q.reject(new Error(`Worker ${worker.id} exited with code ${code}`));
                    });
                    this.workerQueue = this.workerQueue.filter(q => q.worker !== worker);
                    this.replaceWorker(worker); // Replace if unexpected exit
                } else {
                    // Worker exited gracefully, remove it from the pool
                    this.workerPool = this.workerPool.filter(w => w !== worker);
                    console.log(`[AutoSummarizePlugin] Worker ${worker.id} exited gracefully. Current pool size: ${this.workerPool.length}`);
                }
            });
            this.workerPool.push(worker);
        }
        console.log(`[AutoSummarizePlugin] Worker pool initialized with ${this.workerPool.length} workers.`);
    }

    /**
     * Replaces a failed or exited worker with a new one to maintain pool size.
     * @param {Worker} oldWorker - The worker instance to replace.
     */
    replaceWorker(oldWorker) {
        // Ensure the old worker is terminated if it's still active
        try {
            oldWorker.terminate();
        } catch (e) {
            console.warn(`[AutoSummarizePlugin] Error terminating old worker ${oldWorker.id}: ${e.message}`);
        }

        // Remove old worker from the pool array
        this.workerPool = this.workerPool.filter(w => w !== oldWorker);

        // Create a new worker and add it to the pool, re-attaching listeners
        const newWorker = new Worker(path.resolve(__dirname, 'summarize-worker.js'));
        newWorker.isBusy = false;
        newWorker.id = `worker-${this.workerPool.length + 1}-${Date.now()}`; // New unique ID

        // Re-attach event listeners (copy-pasted for clarity)
        newWorker.on('message', (message) => {
            const { task, result, error, stack } = message;
            const resolverIndex = this.workerQueue.findIndex(q => q.task === task && q.worker === newWorker);
            if (resolverIndex !== -1) {
                const taskEntry = this.workerQueue[resolverIndex];
                if (taskEntry.timeoutId) clearTimeout(taskEntry.timeoutId);
                if (error) { const err = new Error(error); err.stack = stack; resolver.reject(err); } else { resolver.resolve(result); }
                newWorker.isBusy = false;
                this.workerQueue.splice(resolverIndex, 1);
                this.processNextWorkerTask();
            } else {
                console.warn(`[AutoSummarizePlugin] Received unexpected message from NEW worker ${newWorker.id} for task '${task}'.`);
            }
        });
        newWorker.on('error', (err) => {
            console.error(`[AutoSummarizePlugin] NEW Worker ${newWorker.id} error: ${err.message}`, err.stack);
            this.workerQueue.filter(q => q.worker === newWorker).forEach(q => { if (q.timeoutId) clearTimeout(q.timeoutId); q.reject(err); });
            this.workerQueue = this.workerQueue.filter(q => q.worker !== newWorker);
            this.replaceWorker(newWorker);
        });
        newWorker.on('exit', (code) => {
            if (code !== 0) {
                console.error(`[AutoSummarizePlugin] NEW Worker ${newWorker.id} exited with code ${code}.`);
                this.workerQueue.filter(q => q.worker === newWorker).forEach(q => { if (q.timeoutId) clearTimeout(q.timeoutId); q.reject(new Error(`Worker ${newWorker.id} exited with code ${code}`)); });
                this.workerQueue = this.workerQueue.filter(q => q.worker !== newWorker);
                this.replaceWorker(newWorker);
            } else {
                this.workerPool = this.workerPool.filter(w => w !== newWorker);
                console.log(`[AutoSummarizePlugin] NEW Worker ${newWorker.id} exited gracefully.`);
            }
        });

        this.workerPool.push(newWorker);
        console.log(`[AutoSummarizePlugin] Replaced worker ${oldWorker.id} with ${newWorker.id}. Current pool size: ${this.workerPool.length}`);
        this.processNextWorkerTask(); // Attempt to process any queued tasks with the new worker
    }

    /**
     * Terminates all active worker threads in the pool.
     * This should be called when the plugin or application is shutting down.
     */
    terminateWorkerPool() {
        console.log('[AutoSummarizePlugin] Terminating worker pool...');
        this.workerPool.forEach(worker => {
            try {
                worker.terminate();
                console.log(`[AutoSummarizePlugin] Worker ${worker.id} terminated.`);
            } catch (e) {
                console.error(`[AutoSummarizePlugin] Error terminating worker ${worker.id}: ${e.message}`);
            }
        });
        this.workerPool = []; // Clear the pool
        this.workerQueue = []; // Clear any pending tasks
    }

    /**
     * Delegates a task to an available worker thread or queues it if all workers are busy.
     * Returns a Promise that resolves with the worker's result or rejects on error/timeout.
     * @param {string} task - The name of the task to perform in the worker (e.g., 'parseDiff', 'processFile').
     * @param {Object} data - The data payload to send to the worker.
     * @param {number} [taskTimeout] - Optional: specific timeout for this task in ms. Overrides global.
     * @returns {Promise<any>} A promise that resolves with the worker's result.
     */
    runInWorker(task, data, taskTimeout = this.config.workerTaskTimeout) {
        return new Promise((resolve, reject) => {
            const taskEntry = { task, data, resolve, reject, worker: null, timeoutId: null };
            this.workerQueue.push(taskEntry); // Always push to queue first

            // Set a timeout for the task
            taskEntry.timeoutId = setTimeout(() => {
                // If the task is still in the queue (either waiting or assigned but not finished)
                const index = this.workerQueue.indexOf(taskEntry);
                if (index !== -1) {
                    this.workerQueue.splice(index, 1); // Remove from queue
                    if (taskEntry.worker && taskEntry.worker.isBusy) {
                        taskEntry.worker.isBusy = false; // Free up the worker
                        console.warn(`[AutoSummarizePlugin] Worker ${taskEntry.worker.id} for task '${task}' timed out. Attempting to replace worker.`);
                        this.replaceWorker(taskEntry.worker); // Replace timed out worker
                    }
                    reject(new Error(`Worker task '${task}' timed out after ${taskTimeout}ms`));
                }
            }, taskTimeout);

            this.processNextWorkerTask(); // Attempt to process immediately if a worker is available
        });
    }

    /**
     * Attempts to process the next task in the queue if a worker becomes available.
     * Called when a worker finishes a task or a new worker is added.
     */
    processNextWorkerTask() {
        const idleWorker = this.workerPool.find(worker => !worker.isBusy);
        // Find the first task in the queue that hasn't been assigned a worker yet
        const nextQueuedTask = this.workerQueue.find(q => q.worker === null);

        if (idleWorker && nextQueuedTask) {
            idleWorker.isBusy = true;
            nextQueuedTask.worker = idleWorker; // Assign the worker to this task

            // Clear the task's timeout if it was waiting (it's now actively being processed)
            if (nextQueuedTask.timeoutId) {
                clearTimeout(nextQueuedTask.timeoutId);
                nextQueuedTask.timeoutId = null; // Mark as cleared
            }

            // Send the message to the worker
            idleWorker.postMessage({ task: nextQueuedTask.task, data: nextQueuedTask.data });
        }
    }


    /**
     * Main entry point - production-grade with full error handling
     * @param {Object} prData - PR data including diff, metadata
     * @param {string} chatId - current chat session identifier
     * @param {Object} options - processing options
     * @returns {Object} comprehensive summary payload
     */
    async summarize(prData, chatId = null, options = {}) {
        const startTime = Date.now();

        try {
            this.validateInput(prData);

            const parsedDiff = await this.robustDiffParsing(prData.diff);
            const summaryMode = options.mode || this.detectOptimalMode(prData, parsedDiff);

            const [summary, flags, metrics, relatedArchives] = await Promise.all([
                this.generateAdaptiveSummary(parsedDiff, prData, summaryMode),
                this.runInWorker('detectSecurityFlags', { parsedDiff, prData, config: this.config }, this.config.workerTaskTimeout * 2), // Longer timeout for security
                this.config.includeMetrics ? this.calculateMetrics(parsedDiff) : null,
                this.config.enableCrossChat ? this.findRelatedArchives(prData) : []
            ]);

            const riskScore = this.calculateRiskScore(flags, metrics, parsedDiff);

            const summaryPayload = {
                summary,
                flags,
                riskScore,
                metrics,
                relatedArchives,
                metadata: {
                    filesChanged: prData.filesChanged || this.extractFileList(parsedDiff),
                    author: prData.author,
                    title: prData.title,
                    prNumber: prData.prNumber,
                    summaryHash: this.hashSummary(summary),
                    timestamp: new Date().toISOString(),
                    chatId: chatId,
                    projectId: this.config.projectId,
                    summaryMode: summaryMode,
                    processingTime: Date.now() - startTime,
                    version: '0.3.0'
                }
            };

            if (this.config.archiveEnabled) {
                setImmediate(() => this.archiveManager.store(summaryPayload));
            }
            this.performanceMetrics.recordSummary(Date.now() - startTime, parsedDiff);

            return summaryPayload;

        } catch (error) {
            const errorContext = {
                error: error.message,
                stack: error.stack,
                prNumber: prData?.prNumber,
                author: prData?.author,
                filesCount: prData?.filesChanged?.length,
                diffSize: prData?.diff?.length,
                processingTime: Date.now() - startTime,
                timestamp: new Date().toISOString()
            };
            console.error('[AutoSummarizePlugin] Error during summarization:', errorContext);
            return this.createErrorFallback(prData, error, errorContext);
        }
    }

    /**
     * Robust diff parsing with multiple fallback strategies.
     * The manual parsing fallback is now offloaded to a worker.
     * @param {string} diffContent - raw diff content
     * @returns {Object} parsed diff object
     */
    async robustDiffParsing(diffContent) {
        const cacheKey = this.hashSummary(diffContent.substring(0, 1000));
        if (this.diffParserCache.has(cacheKey)) {
            return this.diffParserCache.get(cacheKey);
        }

        const parseStrategies = [
            async () => { return unifiedDiffParser(diffContent); },
            async () => { return this.runInWorker('parseDiff', { diffContent }, this.config.workerTaskTimeout); }
        ];

        for (const [index, strategy] of parseStrategies.entries()) {
            try {
                const result = await Promise.race([
                    strategy(),
                    new Promise((_, reject) =>
                        setTimeout(() => reject(new Error('Parse timeout')), this.config.workerTaskTimeout) // Use worker timeout
                    )
                ]);

                if (this.validateParsedDiff(result)) {
                    this.diffParserCache.set(cacheKey, result);
                    return result;
                }
            } catch (error) {
                console.warn(`[AutoSummarizePlugin] Parse strategy ${index + 1} failed:`, error.message);
                continue;
            }
        }
        throw new Error('All diff parsing strategies failed');
    }

    /**
     * Adaptive summary generation based on context
     * @param {Object} parsedDiff - parsed diff data
     * @param {Object} prData - PR metadata
     * @param {string} mode - summarization mode
     * @returns {string} formatted summary
     */
    async generateAdaptiveSummary(parsedDiff, prData, mode) {
        const changes = await this.extractChanges(parsedDiff);
        switch (mode) {
            case 'agent': return this.generateAgentSummary(changes, prData);
            case 'human': return this.generateHumanSummary(changes, prData);
            case 'adaptive': default: return this.generateAdaptiveFormat(changes, prData);
        }
    }

    /**
     * Enhanced security flag detection, now fully offloaded to a worker.
     * This method acts as a wrapper to call the worker for the heavy lifting.
     * @param {Object} parsedDiff - parsed diff data
     * @param {Object} prData - PR metadata
     * @returns {Array} security flags with risk scores
     */
    async detectSecurityFlags(parsedDiff, prData) {
        // All security flagging logic is handled by detectSecurityFlagsWorker in src/utils/worker-tasks.js
        return this.runInWorker('detectSecurityFlags', { parsedDiff, prData, config: this.config }, this.config.workerTaskTimeout * 2);
    }

    /**
     * Calculate comprehensive risk score
     * @param {Array} flags - security flags
     * @param {Object} metrics - code metrics
     * @param {Object} parsedDiff - parsed diff
     * @returns {Object} risk assessment
     */
    calculateRiskScore(flags, metrics, parsedDiff) {
        let totalRisk = 0;
        let maxSingleRisk = 0;
        const severityWeights = { critical: 10, high: 8, medium: 5, low: 2 };

        flags.forEach(flag => {
            const weight = severityWeights[flag.severity] || 2;
            totalRisk += weight;
            maxSingleRisk = Math.max(maxSingleRisk, weight);
        });

        if (metrics) {
            if (metrics.linesChanged > 500) totalRisk += 2;
            if (metrics.filesChanged > 20) totalRisk += 1;
            if (metrics.deletionRatio > 0.5) totalRisk += 1;
        }
        const normalizedRisk = Math.min(totalRisk / 5, 10);
        return {
            overall: parseFloat(normalizedRisk.toFixed(1)),
            category: this.categorizeRisk(normalizedRisk),
            maxSingleFlag: maxSingleRisk,
            flagCount: flags.length,
            breakdown: {
                security: flags.filter(f => ['critical', 'high'].includes(f.severity)).length,
                complexity: metrics?.complexityScore || 0,
                scale: metrics?.linesChanged || 0
            }
        };
    }

    /**
     * Generate agent-optimized summary (structured, parseable)
     * @param {Array} changes - extracted changes
     * @param {Object} prData - PR metadata
     * @returns {string} agent-friendly summary
     */
    generateAgentSummary(changes, prData) {
        const summary = {
            type: 'pr_summary',
            version: '1.0',
            data: {
                files_modified: changes.fileChanges.map(fc => ({
                    path: fc.filePath,
                    additions: fc.adds,
                    deletions: fc.dels,
                    change_type: this.classifyFileChange(fc)
                })),
                key_changes: changes.keyChanges.slice(0, 10),
                impact_assessment: {
                    scope: this.assessChangeScope(changes),
                    risk_level: this.assessChangeRisk(changes),
                    testing_needed: this.suggestTesting(changes)
                }
            }
        };
        return JSON.stringify(summary, null, 2);
    }

    /**
     * Generate human-readable summary
     * @param {Array} changes - extracted changes
     * @param {Object} prData - PR metadata
     * @returns {string} human-friendly summary
     */
    generateHumanSummary(changes, prData) {
        const sections = [];
        sections.push(`📋 **PR Summary: ${prData.title || 'Untitled'}**`);
        sections.push(`Author: ${prData.author || 'Unknown'}`);
        sections.push('');
        if (changes.keyChanges.length > 0) {
            sections.push('🔧 **Key Changes:**');
            changes.keyChanges.slice(0, 8).forEach(change => { sections.push(`• ${change}`); });
            sections.push('');
        }
        if (changes.fileChanges.length > 0) {
            sections.push('📁 **Files Modified:**');
            changes.fileChanges.slice(0, 10).forEach(fc => {
                const changeType = this.classifyFileChange(fc);
                sections.push(`• ${fc.filePath} (${fc.adds}+ ${fc.dels}- ${changeType})`);
            });
            sections.push('');
        }
        sections.push('📊 **Impact Assessment:**');
        sections.push(`• Scope: ${this.assessChangeScope(changes)}`);
        sections.push(`• Risk: ${this.assessChangeRisk(changes)}`);
        sections.push(`• Testing: ${this.suggestTesting(changes)}`);
        return sections.join('\n');
    }

    /**
     * Extract changes with batching for performance, offloading file processing to workers.
     * @param {Object} parsedDiff - parsed diff
     * @returns {Object} structured changes
     */
    async extractChanges(parsedDiff) {
        const fileChanges = [];
        const keyChanges = [];
        const batches = this.batchFiles(parsedDiff.files || [], this.config.batchSize);

        for (const batch of batches) {
            const batchPromises = batch.map(file =>
                this.runInWorker('processFile', { file, config: this.config }, this.config.workerTaskTimeout)
            );
            const batchResults = await Promise.all(batchPromises);

            batchResults.forEach(result => {
                fileChanges.push(result.fileChange);
                keyChanges.push(...result.keyChanges);
            });
        }
        return { fileChanges, keyChanges };
    }

    /**
     * Calculate comprehensive code metrics
     * @param {Object} parsedDiff - parsed diff
     * @returns {Object} code metrics
     */
    calculateMetrics(parsedDiff) {
        let totalLines = 0;
        let addedLines = 0;
        let deletedLines = 0;
        let filesChanged = 0;
        let complexityScore = 0;

        for (const file of parsedDiff.files || []) {
            filesChanged++;
            for (const hunk of file.hunks || []) {
                for (const line of hunk.lines || []) {
                    totalLines++;
                    if (line.type === 'add') {
                        addedLines++;
                        complexityScore += this.calculateLineComplexity(line.content);
                    } else if (line.type === 'del') {
                        deletedLines++;
                    }
                }
            }
        }
        return {
            linesChanged: addedLines + deletedLines,
            linesAdded: addedLines,
            linesDeleted: deletedLines,
            filesChanged,
            additionRatio: totalLines > 0 ? addedLines / totalLines : 0,
            deletionRatio: totalLines > 0 ? deletedLines / totalLines : 0,
            complexityScore: parseFloat((complexityScore / Math.max(addedLines, 1)).toFixed(2)),
            changeSize: this.categorizeChangeSize(addedLines + deletedLines)
        };
    }

    /**
     * Calculate line complexity score
     * @param {string} content - line content
     * @returns {number} complexity score
     */
    calculateLineComplexity(content) {
        let score = 1;
        const complexPatterns = [
            /if\s*\(/g, /else/g, /for\s*\(/g, /while\s*\(/g, /switch\s*\(/g,
            /catch\s*\(/g, /&&/g, /\|\|/g, /\?.*:/g
        ];
        complexPatterns.forEach(pattern => {
            const matches = content.match(pattern);
            if (matches) score += matches.length;
        });
        return score;
    }

    /**
     * Validate input with comprehensive checks
     * @param {Object} prData - PR data to validate
     */
    validateInput(prData) {
        if (!prData) { throw new Error('PR data is required'); }
        if (!prData.diff || typeof prData.diff !== 'string') { throw new Error('Valid diff content is required'); }
        if (prData.diff.length > 10 * 1024 * 1024) { throw new Error('Diff content exceeds maximum size limit'); }
    }

    /**
     * Create error fallback response
     * @param {Object} prData - original PR data
     * @param {Error} error - the error that occurred
     * @param {Object} context - error context
     * @returns {Object} fallback response
     */
    createErrorFallback(prData, error, context) {
        return {
            summary: `⚠️ Processing error occurred. Manual review recommended.\nPR: ${prData?.title || 'Unknown'}\nFiles: ${prData?.filesChanged?.length || 0}`,
            flags: [{
                keyword: 'processing_error',
                severity: 'medium',
                file: 'system',
                line: error.message,
                context: 'Plugin processing failed'
            }],
            riskScore: {
                overall: 5.0,
                category: 'unknown',
                flagCount: 1,
                breakdown: { security: 0, complexity: 0, scale: 0 }
            },
            metadata: {
                error: true,
                errorContext: context,
                filesChanged: prData?.filesChanged || [],
                author: prData?.author || 'unknown',
                title: prData?.title || 'Error Processing PR',
                timestamp: new Date().toISOString(),
                version: '0.3.0'
            }
        };
    }

    // Utility methods (these remain on the main thread as they are lightweight)
    hashSummary(summaryText) {
        return crypto.createHash('sha256').update(summaryText).digest('hex');
    }

    categorizeChangeSize(lines) {
        if (lines < 10) return 'small';
        if (lines < 100) return 'medium';
        if (lines < 500) return 'large';
        return 'extra-large';
    }

    categorizeRisk(score) {
        if (score >= 8) return 'critical';
        if (score >= 6) return 'high';
        if (score >= 4) return 'medium';
        if (score >= 2) return 'low';
        return 'minimal';
    }

    /**
     * Validates the structure and basic content of a parsed diff object.
     * This method remains on the main thread as it's a quick validation after parsing.
     */
    validateParsedDiff(parsedDiff) {
        if (!parsedDiff || typeof parsedDiff !== 'object') {
            console.warn('[AutoSummarizePlugin] Validation failed: parsedDiff is not an object.');
            return false;
        }
        if (!Array.isArray(parsedDiff.files)) {
            console.warn('[AutoSummarizePlugin] Validation failed: parsedDiff.files is not an array.');
            return false;
        }
        if (parsedDiff.files.length === 0) {
            console.warn('[AutoSummarizePlugin] Validation warning: parsedDiff.files array is empty. No changes detected?');
        }
        for (let i = 0; i < Math.min(parsedDiff.files.length, 5); i++) {
            const file = parsedDiff.files[i];
            if (!file || typeof file !== 'object' || typeof file.filePath !== 'string' || !Array.isArray(file.hunks)) {
                console.warn(`[AutoSummarizePlugin] Validation failed: Malformed file object at index ${i}.`);
                return false;
            }
            for (let j = 0; j < Math.min(file.hunks.length, 5); j++) {
                const hunk = file.hunks[j];
                if (!hunk || typeof hunk !== 'object' || !Array.isArray(hunk.lines)) {
                    console.warn(`[AutoSummarizePlugin] Validation failed: Malformed hunk object at file ${file.filePath}, hunk index ${j}.`);
                    return false;
                }
                for (let k = 0; k < Math.min(hunk.lines.length, 5); k++) {
                    const line = hunk.lines[k];
                    if (!line || typeof line !== 'object' || typeof line.type !== 'string' || typeof line.content !== 'string') {
                        console.warn(`[AutoSummarizePlugin] Validation failed: Malformed line object at file ${file.filePath}, hunk ${j}, line index ${k}.`);
                        return false;
                    }
                    if (!['add', 'del', 'context'].includes(line.type)) {
                        console.warn(`[AutoSummarizePlugin] Validation failed: Invalid line type '${line.type}' at file ${file.filePath}, hunk ${j}, line index ${k}.`);
                        return false;
                    }
                }
            }
        }
        return true;
    }

    /**
     * Extracts a clean list of file paths that have been modified in the diff.
     */
    extractFileList(parsedDiff) {
        if (!parsedDiff || !Array.isArray(parsedDiff.files)) {
            return [];
        }
        const files = new Set(parsedDiff.files.map(file => file.filePath).filter(Boolean));
        return Array.from(files);
    }

    /**
     * Classifies the type of change for a given file based on additions and deletions.
     */
    classifyFileChange(fileChange) {
        const { adds, dels, filePath } = fileChange;
        if (adds > 0 && dels === 0) { return 'addition'; }
        if (dels > 0 && adds === 0) { return 'deletion'; }
        if (adds > 0 && dels > 0) {
            if (adds > 50 && dels > 50 && filePath && (filePath.includes('->') || filePath.includes('=>'))) {
                return 'rename/move';
            }
            return 'modification';
        }
        return 'unknown';
    }

    /**
     * Detects the optimal summarization mode ('human' or 'agent') based on PR data.
     */
    detectOptimalMode(prData, parsedDiff) {
        const aiAuthors = ['Mokobot', 'MokoHub-Agent', 'github-actions[bot]', 'dependabot[bot]'];
        if (prData.author && aiAuthors.includes(prData.author.toLowerCase())) { return 'agent'; }
        if (Array.isArray(prData.labels)) {
            const agentLabels = ['bot-pr', 'ci-automation', 'auto-merge', 'skip-human-review'];
            if (prData.labels.some(label => agentLabels.includes(label.toLowerCase()))) { return 'agent'; }
        }
        const metrics = this.calculateMetrics(parsedDiff);
        if (metrics.linesChanged > 500 && metrics.filesChanged > 10 && metrics.additionRatio > 0.9) { return 'agent'; }
        if (metrics.linesChanged === 0 && metrics.filesChanged === 0) { return 'human'; }
        return this.config.summaryMode || 'human';
    }

    /**
     * Assess scope of changes
     * @param {Object} changes - extracted changes
     * @returns {string} scope assessment
     */
    assessChangeScope(changes) {
        const totalFiles = changes.fileChanges.length;
        const totalLines = changes.fileChanges.reduce((sum, fc) => sum + fc.adds + fc.dels, 0);

        if (totalLines < 20 && totalFiles < 3) return 'small (localized)';
        if (totalLines < 200 && totalFiles < 10) return 'medium (contained)';
        if (totalLines < 1000 && totalFiles < 30) return 'large (multi-file)';
        return 'extensive (system-wide)';
    }

    /**
     * Assess risk level of changes
     * @param {Object} changes - extracted changes
     * @returns {string} risk assessment
     */
    assessChangeRisk(changes) {
        const criticalFiles = changes.fileChanges.filter(fc =>
            /auth|security|payment|admin|config/i.test(fc.filePath)
        );

        const largeChanges = changes.fileChanges.filter(fc =>
            fc.adds + fc.dels > 100
        );

        if (criticalFiles.length > 0) return 'High - Security-sensitive files';
        if (largeChanges.length > 3) return 'Medium - Large modifications';
        if (changes.fileChanges.length > 15) return 'Medium - Many files affected';
        return 'Low - Standard changes';
    }

    /**
     * Suggest testing approach
     * @param {Object} changes - extracted changes
     * @returns {string} testing suggestions
     */
    suggestTesting(changes) {
        const testFiles = changes.fileChanges.filter(fc =>
            /test|spec/i.test(fc.filePath)
        );

        const frontendFiles = changes.fileChanges.filter(fc =>
            /\.(jsx?|tsx?|vue|svelte)$/i.test(fc.filePath)
        );

        const backendFiles = changes.fileChanges.filter(fc =>
            /\.(py|java|go|php|rb|cs)$/i.test(fc.filePath)
        );

        const suggestions = [];

        if (testFiles.length === 0) suggestions.push('Unit tests needed');
        if (frontendFiles.length > 0) suggestions.push('UI testing recommended');
        if (backendFiles.length > 0) suggestions.push('API testing required');
        if (changes.fileChanges.some(fc => /database|migration/i.test(fc.filePath))) {
            suggestions.push('Database migration testing');
        }

        return suggestions.length > 0 ? suggestions.join(', ') : 'Standard testing sufficient';
    }

    /**
     * Batch files into chunks for processing
     * @param {Array} files - files to batch
     * @param {number} batchSize - size of each batch
     * @returns {Array} batched files
     */
    batchFiles(files, batchSize) {
        const batches = [];
        for (let i = 0; i < files.length; i += batchSize) {
            batches.push(files.slice(i, i + batchSize));
        }
        return batches;
    }

    /**
     * Count total lines in parsed diff
     * @param {Object} parsedDiff - parsed diff object
     * @returns {number} total line count
     */
    countTotalLines(parsedDiff) {
        return (parsedDiff.files || []).reduce((total, file) => {
            return total + (file.hunks || []).reduce((fileTotal, hunk) => {
                return fileTotal + (hunk.lines || []).length;
            }, 0);
        }, 0);
    }

    /**
     * Test worker thread functionality with expanded edge cases.
     * @returns {Object} test results
     */
    async testWorkerIntegration() {
        console.log('🧪 Testing worker thread integration...');

        const testResults = {
            parseDiff_success: { success: false, duration: 0, error: null },
            parseDiff_error: { success: false, duration: 0, error: null },
            processFile_add: { success: false, duration: 0, error: null },
            processFile_del: { success: false, duration: 0, error: null },
            processFile_empty: { success: false, duration: 0, error: null },
            detectSecurityFlags_basic: { success: false, duration: 0, error: null },
            detectSecurityFlags_comment: { success: false, duration: 0, error: null },
            detectSecurityFlags_multiple: { success: false, duration: 0, error: null },
            detectSecurityFlags_error: { success: false, duration: 0, error: null },
        };

        // Test 1.1: Parse Diff - Success Case (using manualDiffParseWorker via runInWorker)
        try {
            const startTime = Date.now();
            const testDiff = `--- a/test.js\n+++ b/test.js\n@@ -1,3 +1,5 @@\n+const password = 'hardcoded123';\n function test() {\n    console.log('test');\n+   delete user.data;\n }`;
            const parsedResult = await this.runInWorker('parseDiff', { diffContent: testDiff });
            testResults.parseDiff_success.success = !!parsedResult.files && parsedResult.files.length > 0 && parsedResult.files[0].hunks.length > 0;
            testResults.parseDiff_success.duration = Date.now() - startTime;
            if (!testResults.parseDiff_success.success) {
                testResults.parseDiff_success.error = 'Parsed result was empty or malformed.';
            }
        } catch (error) {
            console.error('❌ parseDiff_success test failed:', error.message);
            testResults.parseDiff_success.error = error.message;
        }

        // Test 1.2: Parse Diff - Error Case (malformed input to worker)
        try {
            const startTime = Date.now();
            // Pass a non-string to trigger an error in the worker's manualDiffParseWorker
            await this.runInWorker('parseDiff', { diffContent: null });
            testResults.parseDiff_error.success = false; // Should not reach here
        } catch (error) {
            testResults.parseDiff_error.success = true; // Expected to catch an error
            testResults.parseDiff_error.duration = Date.now() - startTime;
            testResults.parseDiff_error.error = error.message;
            console.log(`✅ parseDiff_error test passed (expected error): ${error.message}`);
        }


        // Test 2.1: Process File - Additions Only
        try {
            const startTime = Date.now();
            const testFile = { filePath: 'new_feature.js', hunks: [{ lines: [{ type: 'add', content: 'const newFunction = () => {}' }] }] };
            const processResult = await this.runInWorker('processFile', { file: testFile, config: this.config });
            testResults.processFile_add.success = processResult.fileChange.adds === 1 && processResult.fileChange.dels === 0 && processResult.keyChanges.length > 0;
            testResults.processFile_add.duration = Date.now() - startTime;
        } catch (error) {
            console.error('❌ processFile_add test failed:', error.message);
            testResults.processFile_add.error = error.message;
        }

        // Test 2.2: Process File - Deletions Only
        try {
            const startTime = Date.now();
            const testFile = { filePath: 'old_code.js', hunks: [{ lines: [{ type: 'del', content: 'const oldFunction = () => {}' }] }] };
            const processResult = await this.runInWorker('processFile', { file: testFile, config: this.config });
            testResults.processFile_del.success = processResult.fileChange.adds === 0 && processResult.fileChange.dels === 1 && processResult.keyChanges.length > 0;
            testResults.processFile_del.duration = Date.now() - startTime;
        } catch (error) {
            console.error('❌ processFile_del test failed:', error.message);
            testResults.processFile_del.error = error.message;
        }

        // Test 2.3: Process File - Empty File Changes
        try {
            const startTime = Date.now();
            const testFile = { filePath: 'empty.js', hunks: [{ lines: [] }] };
            const processResult = await this.runInWorker('processFile', { file: testFile, config: this.config });
            testResults.processFile_empty.success = processResult.fileChange.adds === 0 && processResult.fileChange.dels === 0 && processResult.keyChanges.length === 0;
            testResults.processFile_empty.duration = Date.now() - startTime;
        } catch (error) {
            console.error('❌ processFile_empty test failed:', error.message);
            testResults.processFile_empty.error = error.message;
        }

        // Test 3.1: Detect Security Flags - Basic Detection
        try {
            const startTime = Date.now();
            const testParsedDiff = {
                files: [{
                    filePath: 'auth.js',
                    hunks: [{
                        lines: [
                            { type: 'add', content: "const password = 'secret123';" },
                            { type: 'add', content: "eval(userInput);" }
                        ]
                    }]
                }]
            };
            const flagsResult = await this.runInWorker('detectSecurityFlags', {
                parsedDiff: testParsedDiff,
                prData: { title: 'Test PR', author: 'test@example.com', labels: [] },
                config: this.config
            });
            testResults.detectSecurityFlags_basic.success = Array.isArray(flagsResult) && flagsResult.length >= 2 &&
                flagsResult.some(f => f.keyword === 'hardcoded_secret') && flagsResult.some(f => f.keyword === 'code_injection');
            testResults.detectSecurityFlags_basic.duration = Date.now() - startTime;
        } catch (error) {
            console.error('❌ detectSecurityFlags_basic test failed:', error.message);
            testResults.detectSecurityFlags_basic.error = error.message;
        }

        // Test 3.2: Detect Security Flags - Keyword in Comment (should have lower weight/severity)
        try {
            const startTime = Date.now();
            const testParsedDiff = {
                files: [{
                    filePath: 'utils.js',
                    hunks: [{
                        lines: [
                            { type: 'add', content: "// TODO: Remove hardcoded password later" }
                        ]
                    }]
                }]
            };
            const flagsResult = await this.runInWorker('detectSecurityFlags', {
                parsedDiff: testParsedDiff,
                prData: { title: 'Test PR', author: 'test@example.com', labels: [] },
                config: this.config
            });
            testResults.detectSecurityFlags_comment.success = Array.isArray(flagsResult) && flagsResult.length > 0 &&
                flagsResult.some(f => f.keyword === 'password' && f.severity === 'low'); // Expect low severity due to comment
            testResults.detectSecurityFlags_comment.duration = Date.now() - startTime;
        } catch (error) {
            console.error('❌ detectSecurityFlags_comment test failed:', error.message);
            testResults.detectSecurityFlags_comment.error = error.message;
        }

        // Test 3.3: Detect Security Flags - Multiple Keywords on one line / consolidation
        try {
            const startTime = Date.now();
            const testParsedDiff = {
                files: [{
                    filePath: 'api/user.js',
                    hunks: [{
                        lines: [
                            { type: 'add', content: "const adminToken = 'abc'; // admin token for auth" }
                        ]
                    }]
                }]
            };
            const flagsResult = await this.runInWorker('detectSecurityFlags', {
                parsedDiff: testParsedDiff,
                prData: { title: 'Test PR', author: 'test@example.com', labels: [] },
                config: this.config
            });
            testResults.detectSecurityFlags_multiple.success = Array.isArray(flagsResult) && flagsResult.length >= 2 &&
                flagsResult.some(f => f.keyword === 'hardcoded_secret') && flagsResult.some(f => f.keyword === 'admin');
            testResults.detectSecurityFlags_multiple.duration = Date.now() - startTime;
        } catch (error) {
            console.error('❌ detectSecurityFlags_multiple test failed:', error.message);
            testResults.detectSecurityFlags_multiple.error = error.message;
        }

        // Test 3.4: Detect Security Flags - Error Case (e.g., malformed parsedDiff to worker)
        try {
            const startTime = Date.now();
            // Pass malformed parsedDiff to trigger an error in the worker
            await this.runInWorker('detectSecurityFlags', {
                parsedDiff: { files: [{ filePath: 'bad.js', hunks: [{ lines: [{ type: 'add', content: null }] }] }] }, // Content is null
                prData: {},
                config: this.config
            });
            testResults.detectSecurityFlags_error.success = false; // Should not reach here
        } catch (error) {
            testResults.detectSecurityFlags_error.success = true; // Expected to catch an error
            testResults.detectSecurityFlags_error.duration = Date.now() - startTime;
            testResults.detectSecurityFlags_error.error = error.message;
            console.log(`✅ detectSecurityFlags_error test passed (expected error): ${error.message}`);
        }


        // Summary
        const totalTests = Object.keys(testResults).length;
        const successCount = Object.values(testResults).filter(r => r.success).length;
        console.log(`\n📊 Worker Integration Test Results:`);
        console.log(`✅ Successful tests: ${successCount}/${totalTests}`);
        Object.entries(testResults).forEach(([test, result]) => {
            const status = result.success ? '✅' : '❌';
            const errorMsg = result.error ? ` (Error: ${result.error})` : '';
            console.log(`${status} ${test}: ${result.duration}ms${errorMsg}`);
        });

        return {
            allTestsPassed: successCount === totalTests,
            results: testResults,
            summary: `${successCount}/${totalTests} tests passed`
        };
    }
}

/**
 * Performance Tracker for monitoring plugin efficiency
 */
class PerformanceTracker {
    constructor() {
        this.metrics = [];
    }

    recordSummary(duration, parsedDiff) {
        this.metrics.push({
            timestamp: Date.now(),
            duration,
            filesProcessed: parsedDiff.files?.length || 0,
            linesProcessed: this.countTotalLines(parsedDiff)
        });

        if (this.metrics.length > 100) {
            this.metrics = this.metrics.slice(-100);
        }
    }

    countTotalLines(parsedDiff) {
        return (parsedDiff.files || []).reduce((total, file) => {
            return total + (file.hunks || []).reduce((fileTotal, hunk) => {
                return fileTotal + (hunk.lines || []).length;
            }, 0);
        }, 0);
    }

    getAveragePerformance() {
        if (this.metrics.length === 0) return null;

        const totalDuration = this.metrics.reduce((sum, m) => sum + m.duration, 0);
        const totalFiles = this.metrics.reduce((sum, m) => sum + m.filesProcessed, 0);

        return {
            averageDuration: totalDuration / this.metrics.length,
            averageFilesPerSecond: totalFiles / (totalDuration / 1000),
            samplesCount: this.metrics.length
        };
    }
}

/**
 * Enhanced Archive Manager with better performance and search
 */
class ArchiveManager {
    constructor(config) {
        this.config = config;
        this.archiveFile = path.join(config.archivePath, `${config.projectId}_archives.json`);
        this.indexFile = path.join(config.archivePath, `${config.projectId}_index.json`);
        this.ensureArchiveDirectory();
    }

    async ensureArchiveDirectory() {
        try {
            await fs.mkdir(this.config.archivePath, { recursive: true });
        } catch (error) {
            console.warn('Archive directory creation failed:', error.message);
        }
    }

    async store(summaryPayload) {
        try {
            const archives = await this.loadArchives();
            archives.push({
                id: this.generateId(),
                ...summaryPayload,
                archivedAt: new Date().toISOString()
            });

            if (archives.length > this.config.maxArchiveEntries) {
                archives.splice(0, archives.length - this.config.maxArchiveEntries);
            }

            await this.saveArchives(archives);
            await this.updateIndex(summaryPayload); // This will be implemented next
        } catch (error) {
            console.error('Archive storage failed:', error.message);
        }
    }

    async loadArchives() {
        try {
            const data = await fs.readFile(this.archiveFile, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            return [];
        }
    }

    async saveArchives(archives) {
        const data = JSON.stringify(archives, null, 2);
        await fs.writeFile(this.archiveFile, data, 'utf8');
    }

    generateId() {
        return `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    async updateIndex(summaryPayload) {
        // TODO: Implement index update for faster searches (next task)
        console.log('[ArchiveManager] updateIndex: Placeholder for indexing summaryPayload:', summaryPayload.metadata.summaryHash);
    }

    async findRelatedArchives(prData) {
        // TODO: Implement search over archive (next task)
        console.log('[ArchiveManager] findRelatedArchives: Placeholder for searching related archives for:', prData.title);
        return [];
    }
}

module.exports = AutoSummarizePlugin;

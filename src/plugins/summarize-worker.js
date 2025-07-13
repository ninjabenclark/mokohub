/**
 * summarize-worker.js
 *
 * Worker thread implementation with real worker-task functions.
 * Handles CPU-intensive processing for AutoSummarizePlugin.
 *
 * @version 0.3.0
 */

const { parentPort } = require('worker_threads');
// Import the actual logic from the new worker-tasks utility module
// IMPORTANT: This path will need to be adjusted later when you place the file.
// It assumes summarize-worker.js is in src/plugins and worker-tasks.js is in src/utils
const {
    processFileWorker,
    detectSecurityFlagsWorker,
    manualDiffParseWorker
} = require('../utils/worker-tasks'); // Corrected path: go up one level (..) then into utils

// Main message handler
parentPort.on('message', async ({ task, data }) => {
    try {
        let result;
        switch (task) {
            case 'parseDiff':
                // Parse diff content using manual parser
                result = manualDiffParseWorker(data); // data should contain { diffContent: string }
                break;

            case 'processFile':
                // Process individual file for changes and key modifications
                result = await processFileWorker(data); // data should contain { file: object, config: object }
                break;

            case 'detectSecurityFlags':
                // Detect security patterns and flags in parsed diff
                result = await detectSecurityFlagsWorker(data); // data should contain { parsedDiff: object, prData: object, config: object }
                break;

            default:
                throw new Error(`Unknown task: ${task}`);
        }

        // Send result back to main thread
        parentPort.postMessage({ task, result });

    } catch (error) {
        // Send error details back to main thread
        parentPort.postMessage({
            error: error.message,
            stack: error.stack,
            task: task || 'unknown'
        });
    }
});

// Optional: Handle worker termination gracefully
process.on('SIGTERM', () => {
    parentPort.postMessage({ status: 'worker_terminating' });
    process.exit(0);
});

process.on('SIGINT', () => {
    parentPort.postMessage({ status: 'worker_interrupted' });
    process.exit(0);
});

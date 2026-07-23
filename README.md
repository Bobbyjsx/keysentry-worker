# KeySentry Worker

KeySentry Worker is the high-performance, asynchronous background engine for scanning repositories and finding leaked secrets. It is built on top of [Trigger.dev v3](https://trigger.dev/) for resilient task orchestration and is designed to handle extremely large repositories and highly parallel fan-out operations without blocking or timing out.

## Architecture

The worker uses a separation-of-concerns architecture divided into three primary layers: **Tasks**, **Engines**, and **Core**.

### 1. Tasks (`src/tasks/`)
Tasks are the entry points for the Trigger.dev infrastructure. They handle the orchestration, error handling, retries, and fan-out logic.

* **`githubScanTask`** (`github_fanout.task.ts`):
  The main orchestrator. When a scan is initiated on a user or organization (e.g., `github/bobbyjsx`), this task queries the GitHub API to discover all accessible repositories. It filters out any repositories that have already been scanned for this run, and then dispatches the workload concurrently to `scanSingleRepoTask` via `triggerAndWait`. It pauses compute while waiting for the parallel child tasks to complete, ensuring it does not exceed timeout limits.
  
* **`scanSingleRepoTask`** (`scan_repo.task.ts`):
  The heavy-lifter. Given a specific repository (e.g., `bobbyjsx/keysentry-worker`), this task downloads the repository contents, streams them through the scanning engine, and reports progress back to the central KeySentry API.

### 2. Engines (`src/engines/`)
Engines contain the actual business logic and perform the data processing, network requests, and secret detection.

* **`GithubEngine`**: Handles GitHub API interactions via Octokit. Instead of cloning repositories to disk (which is slow and relies on disk I/O), it downloads repository tarballs (`.tar.gz`) directly into a memory stream, parsing them on-the-fly.
* **`ScannerEngine`**: The core detection system. It takes raw text inputs and evaluates them against the compiled regex patterns to identify secrets, dynamically hiding parts of the matched string to safely hash it for reporting.
* **`PatternEngine`**: Responsible for loading and caching the Gitleaks TOML patterns. This ensures that KeySentry always has the most up-to-date threat signatures available in memory without needing constant disk or network reads.
* **`ScanApiClient`**: A centralized, internal client that abstracts all outbound webhook communications back to the `keysentry-api`. It handles reporting `in_progress` chunks, `failed` timeouts, and `succeeded` states.

### 3. Core (`src/core/`)
Contains shared utilities, configuration loaders, and security services.
* **`config.ts`**: Manages environment variables.
* **`encryption.ts`**: Handles symmetric Fernet encryption/decryption for securely using GitHub Access Tokens passed by the API.

## Data Flow (How a Scan Works)

1. **Trigger**: The user initiates a scan via the frontend. The `keysentry-api` receives the request, stores an `in_progress` scan state, and dispatches a payload to Trigger.dev.
2. **Orchestration**: Trigger.dev spins up the `githubScanTask`. The worker fetches all repositories for the target and triggers N parallel instances of `scanSingleRepoTask`.
3. **Streaming & Scanning**: Each `scanSingleRepoTask` requests the repository tarball from GitHub. As the tarball streams over the network, `tar-stream` and `zlib` extract the files directly into memory.
4. **Detection**: Each file's contents are passed to the `ScannerEngine`. If a leaked key is detected, it is immediately mapped to the exact file and matched pattern.
5. **Progress Webhooks**: While the scan is running, the task periodically POSTs back to `keysentry-api` via `ScanApiClient`, updating the "Files Scanned" and "Keys Found" counters in real-time.
6. **Completion / Failure**: If a task fails or times out, the native Trigger.dev `onFailure` hook cleanly reports the failure back to the API. If all tasks succeed, the orchestrator reports the entire scan as `succeeded`.

## Performance Focus
* **Diskless Scanning**: By using tarball streams, the worker completely avoids writing massive codebases to temporary SSD storage. This allows us to scan massive mono-repos efficiently within small Docker containers or Lambda limits.
* **Trigger Wait-States**: Using `triggerAndWait` for fan-out orchestration means the parent task suspends execution and stops consuming billed compute duration while waiting for child tasks to scan repos in parallel.

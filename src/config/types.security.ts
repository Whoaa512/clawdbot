/**
 * Security configuration types for Clawdbot.
 */

/**
 * Action to take when suspicious content is detected.
 * - "flag": Log and alert, but process normally (model handles it)
 * - "block": Reject with generic response, don't process
 * - "confirm": Pause, alert owner, wait for explicit approval
 */
export type SecurityAction = "flag" | "block" | "confirm";

/**
 * Sensitivity threshold for triggering actions.
 * - "low": Trigger on any suspicious pattern
 * - "medium": Trigger on MEDIUM or HIGH risk patterns (default)
 * - "high": Only trigger on HIGH risk patterns
 */
export type SecurityThreshold = "low" | "medium" | "high";

/**
 * Configuration for external content security (prompt injection protection).
 */
export type ExternalContentSecurityConfig = {
	/** Enable external content security scanning. Default: true */
	enabled?: boolean;

	/** Action to take when suspicious patterns are detected. Default: "flag" */
	action?: SecurityAction;

	/** Sensitivity threshold. Default: "medium" */
	threshold?: SecurityThreshold;

	/** Session key to send alerts to. Default: "main" */
	alertSession?: string;

	/** Per-source configuration */
	sources?: {
		/** Scan content from web_fetch tool. Default: true */
		webFetch?: boolean;
		/** Scan content from browser tool snapshots. Default: true */
		browser?: boolean;
		/** Scan email content from Gmail hooks. Default: true */
		email?: boolean;
		/** Scan webhook payloads. Default: true */
		webhooks?: boolean;
		/** Scan RSS/Atom feed content. Default: true */
		feeds?: boolean;
		/** Scan file reads from untrusted paths. Default: false */
		files?: boolean;
	};

	/** Paths to treat as untrusted (glob patterns). Only used when sources.files is true. */
	untrustedPaths?: string[];
};

/**
 * Top-level security configuration.
 */
export type SecurityConfig = {
	/** External content security (prompt injection protection) */
	externalContent?: ExternalContentSecurityConfig;
};

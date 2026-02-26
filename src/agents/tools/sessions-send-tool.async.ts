import { callGateway } from "../../gateway/call.js";
import { formatErrorMessage } from "../../infra/errors.js";
import { createSubsystemLogger } from "../../logging/subsystem.js";
import { INTERNAL_MESSAGE_CHANNEL } from "../../utils/message-channel.js";
import type { GatewayMessageChannel } from "../../utils/message-channel.js";
import { AGENT_LANE_NESTED } from "../lanes.js";
import { readLatestAssistantReply } from "./agent-step.js";

const log = createSubsystemLogger("agents/sessions-send-async");

/**
 * Async flow for sessions_send: waits for the target session to complete,
 * then injects the response back into the calling session as a system event.
 */
export async function runSessionsSendAsyncFlow(params: {
  targetSessionKey: string;
  displayKey: string;
  message: string;
  waitRunId: string;
  timeoutMs: number;
  requesterSessionKey?: string;
  requesterChannel?: GatewayMessageChannel;
  correlationId: string;
}) {
  const { waitRunId, correlationId } = params;
  try {
    if (!params.requesterSessionKey) {
      log.warn("sessions_send async: no requester session key, cannot deliver response", {
        runId: waitRunId,
        correlationId,
      });
      return;
    }

    // Wait for the target session to finish processing
    const waitMs = Math.min(params.timeoutMs || 60_000, 120_000);
    const wait = await callGateway<{ status: string; error?: string }>({
      method: "agent.wait",
      params: { runId: waitRunId, timeoutMs: waitMs },
      timeoutMs: waitMs + 2000,
    });

    if (wait?.status !== "ok") {
      const errorText = wait?.error ?? wait?.status ?? "unknown error";
      // Inject error event back into caller
      await injectEventIntoSession({
        sessionKey: params.requesterSessionKey,
        text: `[Agent Response from ${params.displayKey}] Error: ${errorText} (correlationId: ${correlationId})`,
      });
      return;
    }

    // Read the reply from the target session
    const reply = await readLatestAssistantReply({
      sessionKey: params.targetSessionKey,
    });

    const responseText = reply?.trim()
      ? `[Agent Response from ${params.displayKey}] ${reply.trim()}`
      : `[Agent Response from ${params.displayKey}] (no reply) (correlationId: ${correlationId})`;

    // Inject the response back into the calling session
    await injectEventIntoSession({
      sessionKey: params.requesterSessionKey,
      text: responseText,
    });

    log.info("sessions_send async: delivered response to caller", {
      runId: waitRunId,
      correlationId,
      requesterSessionKey: params.requesterSessionKey,
      targetSessionKey: params.displayKey,
      hasReply: !!reply,
    });
  } catch (err) {
    log.warn("sessions_send async flow failed", {
      runId: waitRunId,
      correlationId,
      error: formatErrorMessage(err),
    });

    // Best-effort: try to notify the caller about the failure
    if (params.requesterSessionKey) {
      try {
        await injectEventIntoSession({
          sessionKey: params.requesterSessionKey,
          text: `[Agent Response from ${params.displayKey}] Error: async delivery failed - ${formatErrorMessage(err)} (correlationId: ${correlationId})`,
        });
      } catch {
        // Give up silently
      }
    }
  }
}

async function injectEventIntoSession(params: { sessionKey: string; text: string }) {
  await callGateway({
    method: "agent",
    params: {
      message: params.text,
      sessionKey: params.sessionKey,
      channel: INTERNAL_MESSAGE_CHANNEL,
      lane: AGENT_LANE_NESTED,
      deliver: false,
      inputProvenance: {
        kind: "inter_session",
        sourceTool: "sessions_send_async",
      },
    },
    timeoutMs: 10_000,
  });
}

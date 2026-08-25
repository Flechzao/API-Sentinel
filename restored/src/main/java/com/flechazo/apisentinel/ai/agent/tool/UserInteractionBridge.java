package com.flechazo.apisentinel.ai.agent.tool;

import java.util.List;

/**
 * Lets a tool pause and ask the human operator a question, Claude-Code style,
 * instead of guessing. Implemented by the UI layer (ChatInteractionBridge)
 * which renders an inline card in the conversation flow; the tool's background
 * thread blocks on the answer.
 *
 * All methods may be called from ANY thread (they internally hop to the EDT
 * to build the card, then block the calling thread). Each call must be
 * answered or timed out exactly once — bridges enforce a timeout so a
 * missing operator can never wedge an agent loop forever.
 */
public interface UserInteractionBridge {

    /**
     * Two-button confirmation (approve/reject), used by the sandboxed-code
     * gate. Renders the code so the user can make an informed call.
     *
     * @return TRUE approved, FALSE rejected, null = timed out or the bridge
     *         had no UI to show (both must be treated as REJECT by callers —
     *         the safe default for anything that executes local code).
     */
    Boolean askConfirmation(String title, String detail, String code,
                            String approveLabel, String rejectLabel,
                            long timeoutSeconds);

    /**
     * Multiple-choice question (ask_user tool). Options are rendered as
     * buttons; an explicit "skip" affordance means "no answer, keep going".
     *
     * @return the chosen option's index, or null when the user skipped or the
     *         question timed out — callers should proceed autonomously.
     */
    Integer askChoice(String question, String context, List<String> options,
                      long timeoutSeconds);
}

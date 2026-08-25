package com.flechazo.apisentinel.event;

import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.model.ApiEntry;

/**
 * Published when a full Pipeline/Agent analysis (NOT the auto-pilot's
 * lightweight pass) ends with at least one VERIFIED confirmed vuln — the
 * signal for AgentController's cascade hunting: same-flaw sibling endpoints
 * get auto-queued for analysis (P2 of the cluster-hunting upgrade; see
 * payloads/chain-hunting.md, docs/THIRD-PARTY.md).
 *
 * <p>Only ever published with a non-empty confirmed list — suspected-only
 * results must NOT cascade (anti-false-positive: an unverified hunch on one
 * endpoint is not evidence the siblings share it).
 *
 * @param method  HTTP method of the analyzed request ("" when unknown)
 * @param verdict the final, post-VerdictValidator verdict — confirmedVulns()
 *                is non-empty by construction of the publisher
 */
public record ClusterHuntTriggerEvent(
    ApiEntry entry,
    String method,
    FinalVerdict verdict
) {}

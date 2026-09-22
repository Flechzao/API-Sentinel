package com.flechazo.apisentinel.ai.pipeline.evidence;

import java.util.List;

/**
 * The evidence a vulnerability type must (and optionally may) carry.
 *
 * @param required slots that MUST be present, else the finding is demoted to
 *                 suspected with a structured reason
 * @param optional slots that strengthen a finding but are not gated
 */
public record EvidenceRequirement(List<EvidenceField> required, List<EvidenceField> optional) {
    public EvidenceRequirement {
        required = required == null ? List.of() : List.copyOf(required);
        optional = optional == null ? List.of() : List.copyOf(optional);
    }
}

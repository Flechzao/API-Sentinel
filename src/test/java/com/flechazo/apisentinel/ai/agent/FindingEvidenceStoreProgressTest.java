package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.agent.FindingEvidenceStore.ProgressNote;
import com.flechazo.apisentinel.ai.agent.tool.ReadAnalysisNotesTool;
import com.flechazo.apisentinel.ai.agent.tool.UpdateAnalysisNotesTool;
import com.flechazo.apisentinel.logging.LeveledLogger;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards for the free-text progress partition added for context-window
 * rollover (① Phase A). The store now carries a running narrative
 * (hypothesis / blockers / failed payloads / 已测端点) alongside the
 * structured findings, tagged with the context-window id it was written
 * in so a new window can recover only what it is missing.
 */
class FindingEvidenceStoreProgressTest {

    private final FindingEvidenceStore store =
            new FindingEvidenceStore(new LeveledLogger(null));

    @Test
    void appendProgress_tagsWithCurrentWindow_andListRecoversSinceWindow() {
        store.setCurrentWindowId(0);
        store.appendProgress("tested /api/login, no SQLi");
        store.appendProgress("hypothesis: id param reflects in error page");

        store.setCurrentWindowId(1);
        store.appendProgress("blocked by WAF on ' OR 1=1--");
        store.appendProgress("next: try boolean-blind on id");

        // Window 1 only knows what it wrote; to recover the prior narrative
        // it asks for notes written after window 0.
        var recovered = store.listProgress(0);
        assertThat(recovered).extracting(ProgressNote::windowId)
                .containsOnly(1);
        assertThat(recovered).extracting(ProgressNote::text)
                .contains("blocked by WAF on ' OR 1=1--",
                        "next: try boolean-blind on id");

        // Window 2 asking after window 1 gets only its own future — nothing yet.
        store.setCurrentWindowId(2);
        assertThat(store.listProgress(1)).isEmpty();
    }

    @Test
    void appendProgress_blankAndNullIgnored() {
        store.appendProgress(null);
        store.appendProgress("   ");
        store.appendProgress("real note");
        assertThat(store.allProgress()).hasSize(1);
    }

    @Test
    void updateAnalysisNotes_progressAction_persistsAndReadsBack() {
        UpdateAnalysisNotesTool update = new UpdateAnalysisNotesTool(store);
        ReadAnalysisNotesTool read = new ReadAnalysisNotesTool(store);

        store.setCurrentWindowId(3);
        String res = update.execute("{\"action\":\"progress\","
                + "\"text\":\"卡点: /admin 返回 403, 需要先绕过 auth\"}");
        assertThat(res).contains("\"success\":true").contains("\"window\":3");

        // read back via the tool, scoped to this window.
        String back = read.execute("{\"action\":\"progress\",\"sinceWindow\":2}");
        assertThat(back).contains("卡点: /admin 返回 403");
        assertThat(back).contains("\"count\":1");
    }

    @Test
    void updateAnalysisNotes_checkpointPrefixesAndPersists() {
        UpdateAnalysisNotesTool update = new UpdateAnalysisNotesTool(store);
        update.execute("{\"action\":\"checkpoint\",\"text\":\"done recon, 5 endpoints mapped\"}");
        var notes = store.allProgress();
        assertThat(notes).hasSize(1);
        assertThat(notes.get(0).text()).startsWith("[checkpoint]");
    }

    @Test
    void readAnalysisNotes_progressNoNotes_returnsHint() {
        ReadAnalysisNotesTool read = new ReadAnalysisNotesTool(store);
        String back = read.execute("{\"action\":\"progress\"}");
        assertThat(back).contains("\"count\":0");
    }
}

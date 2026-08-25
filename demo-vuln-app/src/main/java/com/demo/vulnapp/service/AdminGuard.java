package com.demo.vulnapp.service;

import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * The "correct" role check for admin-only endpoints — deliberately UNUSED by
 * AdminController (#6 vertical privilege escalation in GROUND_TRUTH.md). This
 * class exists to test whether an analysis tool follows the call graph far
 * enough to notice the real check lives here and was never wired up, rather
 * than assuming a role check exists just because a plausible-looking guard
 * class is present somewhere in the repo.
 */
@Component
public class AdminGuard {

    private static final Set<Integer> ADMIN_USER_IDS = Set.of(3);

    public boolean hasAdminRole(int userId) {
        return ADMIN_USER_IDS.contains(userId);
    }
}

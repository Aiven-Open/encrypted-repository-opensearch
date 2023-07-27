/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import org.opensearch.SpecialPermission;
import org.opensearch.common.CheckedRunnable;

public final class Permissions {

    public static <T> T doPrivileged(final PrivilegedExceptionAction<T> privilegedAction) throws IOException {
        SpecialPermission.check();
        try {
            return AccessController.doPrivileged(privilegedAction);
        } catch (final PrivilegedActionException e) {
            throw (IOException) e.getCause();
        }
    }

    public static void doPrivileged(final CheckedRunnable<IOException> checkedRunnable) throws IOException {
        SpecialPermission.check();
        try {
            AccessController.doPrivileged((PrivilegedExceptionAction<Void>) () -> {
                checkedRunnable.run();
                return null;
            });
        } catch (final PrivilegedActionException e) {
            throw (IOException) e.getCause();
        }
    }
}

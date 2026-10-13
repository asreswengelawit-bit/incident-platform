package com.company.incidentplatform.web;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Binds the request's {@code PlatformUser} -- the end of the 6.2 authorization
 * chain -- to a controller parameter.
 *
 * <p>Present so no controller has to reach into {@code SecurityContextHolder}
 * and cast. The alternative, a helper that returns {@code PlatformUser} or
 * throws, invites each controller to invent its own fallback for the
 * "shouldn't be reachable" case, and the most likely fallback -- treating a
 * missing principal as a null user and passing it down -- is precisely the bug
 * that turns an authentication failure into an unauthenticated read.
 */
@Documented
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface CurrentUser {
}

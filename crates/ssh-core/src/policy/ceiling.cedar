// The rules a deployment does not get to remove.
//
// `forbid` wins over every `permit` in Cedar, so no rule a deployment adds can
// relax these. They are held apart from the replaceable policy because
// replacing that text must not be a way to delete a boundary: a deployment
// writes what is allowed within these rules, not whether they exist.

// The ceiling is what was declared when the session opened and what a human
// approved if one was asked. A command exceeding it is not "privileged work
// pending approval" - it is work outside what anybody agreed to.
@id("session-ceiling")
forbid (principal, action, resource)
when { context.assessment > context.ceiling };

// A command the catalog could not identify never runs unattended. Whether a
// deployment lets it wait for a human is the deployment's to write; running
// it outright is not, because nobody - policy author included - knows what
// they would be permitting.
@id("unidentified-never-runs-unattended")
forbid (principal, action == Action::"run", resource)
when { !context.identified };

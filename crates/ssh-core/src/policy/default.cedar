// The policy this service ships with. A deployment replaces it; this is the
// shape a replacement is expected to keep, and the behaviour if nobody writes
// one.
//
// Scope is carried as a number so it can be ordered: 0 read, 1 mutate,
// 2 privileged. The matching names are also in context for policies that would
// rather read than count.

// Reading runs without a human.
@id("read-runs")
permit (principal, action == Action::"run", resource)
when { context.assessment == 0 };

// Anything that could change the target waits for one. This includes a
// command the catalog could not identify: it carries the maximal assessment,
// so it lands here rather than running. A deployment that would rather refuse
// such commands outright can forbid on `!context.identified`.
@id("changes-wait-for-a-human")
permit (principal, action == Action::"runWithApproval", resource)
when { context.assessment >= 1 };

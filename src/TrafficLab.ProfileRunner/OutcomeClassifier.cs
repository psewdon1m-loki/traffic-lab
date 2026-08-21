internal static class OutcomeClassifier
{
    public const string Pass = "PASS";
    public const string ProxyFail = "PROXY_FAIL";
    public const string UnderlayFail = "UNDERLAY_FAIL";
    public const string TestFailure = "TEST_FAILURE";
    public const string Unknown = "UNKNOWN";

    public static void Apply(RunReport report)
    {
        var directControlAvailable = DirectControlAvailable(report);
        foreach (var profile in report.Profiles)
        {
            foreach (var stage in profile.Stages)
                ClassifyStage(stage, directControlAvailable);
            profile.Outcome = ClassifyProfile(profile, directControlAvailable);
        }
        report.Outcome = ClassifyRun(report, directControlAvailable);
    }

    public static OutcomeDecision ClassifyProfile(ProfileReport profile, bool directControlAvailable)
    {
        if (!directControlAvailable)
            return Decision(UnderlayFail, "DIRECT_CONTROL_UNAVAILABLE",
                "The direct no-proxy control produced no usable HTTPS/IP/STUN evidence, so proxy-specific conclusions are unsafe.",
                "direct baseline unavailable");

        var parse = Stage(profile, "profile.parse");
        var policy = Stage(profile, "profile.policy");
        var validation = Stage(profile, "tunnel.coreValidation");
        var coreStart = Stage(profile, "tunnel.coreStart");
        var unhandled = Stage(profile, "tunnel.unhandled");
        if (Failed(parse) || Failed(policy) || Failed(validation) || Failed(coreStart) || Failed(unhandled))
            return Decision(TestFailure, "TESTER_OR_CONFIGURATION_FAILURE",
                "The tester could not parse, authorize, validate, or start the local client core; the proxy path was not fairly evaluated.",
                FirstFailed(parse, policy, validation, coreStart, unhandled));

        var endpointDns = Stage(profile, "endpoint.dns");
        var endpointTcp = Stage(profile, "endpoint.tcp");
        if (Failed(endpointDns))
            return Decision(ProxyFail, "ENDPOINT_DNS_UNRESOLVED",
                "The direct control worked, but the profile endpoint did not resolve on the tested underlay.", endpointDns!.Stage);
        if (Failed(endpointTcp))
            return Decision(ProxyFail, "ENDPOINT_TCP_UNREACHABLE",
                "The direct control worked, but no TCP connection to the profile endpoint succeeded.", endpointTcp!.Stage);

        var authenticated = Stage(profile, "tunnel.authenticatedEndToEnd");
        if (Passed(authenticated))
            return Decision(Pass, "AUTHENTICATED_E2E_SUCCEEDED",
                "At least one authenticated destination request completed through the tested profile.", authenticated!.Stage);
        if (Passed(endpointTcp) && (Failed(authenticated) || authenticated?.Status == "skipped"))
            return Decision(ProxyFail, "PROTOCOL_AUTH_FAIL",
                "Endpoint TCP was reachable, but an authenticated end-to-end VLESS request was not completed.", authenticated?.Stage ?? "tunnel.authenticatedEndToEnd missing");

        return Decision(Unknown, "INSUFFICIENT_EVIDENCE",
            "The available stages do not distinguish an underlay, proxy-path, authentication, or tester failure.",
            string.Join(", ", profile.Stages.Where(item => item.Status is "failed" or "partial").Select(item => item.Stage).Take(8)));
    }

    private static OutcomeDecision ClassifyRun(RunReport report, bool directControlAvailable)
    {
        if (!directControlAvailable)
            return Decision(UnderlayFail, "DIRECT_CONTROL_UNAVAILABLE",
                "The run has no usable direct-network control; all profile diagnoses are bounded by that underlay failure.",
                "no valid direct exit-IP observation and no direct HTTP/throughput/STUN success");

        var outcomes = report.Profiles.Select(item => item.Outcome).Where(item => item is not null).Cast<OutcomeDecision>().ToArray();
        if (outcomes.Any(item => item.Outcome == Pass))
            return Decision(Pass, "RUN_COMPLETED_WITH_USABLE_PROFILE",
                "The test run completed and at least one profile passed authenticated end-to-end traffic.",
                OutcomeCounts(outcomes));
        if (outcomes.Length > 0 && outcomes.All(item => item.Outcome == TestFailure))
            return Decision(TestFailure, "ALL_PROFILES_TEST_FAILURE",
                "Every scheduled profile was blocked by a tester, policy, parse, or local-core failure.", OutcomeCounts(outcomes));
        if (outcomes.Any(item => item.Outcome == ProxyFail))
            return Decision(ProxyFail, "NO_USABLE_PROFILE",
                "The direct control worked, but no profile completed authenticated end-to-end traffic.", OutcomeCounts(outcomes));
        return Decision(Unknown, "RUN_INCONCLUSIVE",
            "The run completed without enough evidence to assign a proxy or underlay failure.", OutcomeCounts(outcomes));
    }

    private static void ClassifyStage(StageResult stage, bool directControlAvailable)
    {
        if (stage.Status == "passed")
        {
            stage.Outcome = Pass;
            stage.ReasonCode = "CHECK_SUCCEEDED";
            stage.Reason = "The stage's success criterion was directly observed.";
            return;
        }
        if (stage.Status == "skipped")
        {
            stage.Outcome = Unknown;
            stage.ReasonCode = stage.ReasonCode is "DEPENDENCY_NOT_MET" or "NOT_APPLICABLE" or "CONTROL_NOT_APPLICABLE" or "UNSUPPORTED_ON_PLATFORM"
                ? stage.ReasonCode
                : stage.Error?.Contains("unsupported", StringComparison.OrdinalIgnoreCase) == true
                || stage.Error?.Contains("cannot reliably", StringComparison.OrdinalIgnoreCase) == true
                ? "UNSUPPORTED_ON_PLATFORM"
                : stage.Error?.Contains("did not", StringComparison.OrdinalIgnoreCase) == true
                    || stage.Error?.Contains("unavailable", StringComparison.OrdinalIgnoreCase) == true
                    ? "DEPENDENCY_NOT_MET"
                    : "NOT_REQUESTED_OR_NOT_APPLICABLE";
            stage.Reason = stage.Error ?? "The stage was not executed.";
            return;
        }
        if (stage.ReasonCode == "INVALID_TRACEROUTE_OUTPUT")
        {
            stage.Outcome = TestFailure;
            stage.Reason = stage.Error ?? "The traceroute output failed semantic validation.";
            return;
        }
        if (!directControlAvailable && IsRemoteNetworkStage(stage.Stage))
        {
            stage.Outcome = UnderlayFail;
            stage.ReasonCode = "DIRECT_CONTROL_UNAVAILABLE";
            stage.Reason = "The no-proxy control was unavailable, so this remote stage cannot be attributed to the profile.";
            return;
        }
        if (stage.Stage is "profile.parse" or "profile.policy" or "tunnel.localPort" or "tunnel.coreValidation" or "tunnel.coreStart" or "tunnel.unhandled")
        {
            stage.Outcome = TestFailure;
            stage.ReasonCode = "TESTER_OR_CONFIGURATION_FAILURE";
            stage.Reason = stage.Error ?? "The local tester or generated client configuration failed.";
            return;
        }
        if (stage.Stage == "endpoint.tcp")
        {
            stage.Outcome = ProxyFail;
            stage.ReasonCode = "ENDPOINT_TCP_UNREACHABLE";
            stage.Reason = stage.Error ?? "No TCP path to the profile endpoint was observed.";
            return;
        }
        if (stage.Stage == "endpoint.dns")
        {
            stage.Outcome = ProxyFail;
            stage.ReasonCode = "ENDPOINT_DNS_UNRESOLVED";
            stage.Reason = stage.Error ?? "The profile endpoint did not resolve.";
            return;
        }
        if (stage.Stage == "tunnel.authenticatedEndToEnd")
        {
            stage.Outcome = ProxyFail;
            stage.ReasonCode = "PROTOCOL_AUTH_FAIL";
            stage.Reason = stage.Error ?? "The reachable endpoint did not complete authenticated end-to-end traffic.";
            return;
        }
        if (stage.Stage.StartsWith("endpoint.", StringComparison.OrdinalIgnoreCase)
            || stage.Stage.StartsWith("tunnel.", StringComparison.OrdinalIgnoreCase))
        {
            stage.Outcome = stage.Status == "partial" ? Unknown : ProxyFail;
            stage.ReasonCode = stage.Status == "partial" ? "INCONCLUSIVE_REMOTE_CHECK" : "PROXY_SUBCHECK_FAIL";
            stage.Reason = stage.Error ?? "A profile-path subcheck did not meet its success criterion.";
            return;
        }
        stage.Outcome = Unknown;
        stage.ReasonCode = stage.Status == "partial" ? "INCONCLUSIVE_CHECK" : "UNCLASSIFIED_CHECK_FAILURE";
        stage.Reason = stage.Error ?? "The stage result is not sufficient for a causal diagnosis.";
    }

    private static bool DirectControlAvailable(RunReport report)
        => report.DirectBaseline.Any(item => item.Valid)
            || report.Node?.DirectPerformance.Status == "observed";

    private static bool IsRemoteNetworkStage(string name)
        => name.StartsWith("endpoint.", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("camouflage.", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("network.", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("tunnel.", StringComparison.OrdinalIgnoreCase);

    private static StageResult? Stage(ProfileReport profile, string name)
        => profile.Stages.FirstOrDefault(item => item.Stage.Equals(name, StringComparison.OrdinalIgnoreCase));
    private static bool Passed(StageResult? stage) => stage?.Status == "passed";
    private static bool Failed(StageResult? stage) => stage?.Status == "failed";
    private static string FirstFailed(params StageResult?[] stages)
        => stages.FirstOrDefault(Failed)?.Stage ?? "unknown local stage";
    private static string OutcomeCounts(IEnumerable<OutcomeDecision> values)
        => string.Join(", ", values.GroupBy(item => item.Outcome).OrderBy(item => item.Key).Select(item => $"{item.Key}={item.Count()}"));
    private static OutcomeDecision Decision(string outcome, string reasonCode, string reason, string evidence)
        => new() { Outcome = outcome, ReasonCode = reasonCode, Reason = reason, Evidence = [evidence] };
}

internal sealed class OutcomeDecision
{
    public required string Outcome { get; init; }
    public required string ReasonCode { get; init; }
    public required string Reason { get; init; }
    public IReadOnlyList<string> Evidence { get; init; } = [];
}

using System.Collections.Concurrent;
using Fido2NetLib;
using Microsoft.Extensions.Options;

namespace MedSign.Api.Auth.Passkey;

public sealed class PasskeyChallengeStore(IOptions<PasskeyOptions> options, TimeProvider clock)
{
    private readonly PasskeyOptions _options = options.Value;
    private readonly ConcurrentDictionary<(string Username, PasskeyCeremony Ceremony), Entry> _pending = new();

    public void Issue(string username, CredentialCreateOptions ceremony) =>
        Hold(username, PasskeyCeremony.Registration, ceremony);

    public void Issue(string username, AssertionOptions ceremony) =>
        Hold(username, PasskeyCeremony.Assertion, ceremony);

    public CredentialCreateOptions? ConsumeRegistration(string username) =>
        Consume(username, PasskeyCeremony.Registration) as CredentialCreateOptions;

    public AssertionOptions? ConsumeAssertion(string username) =>
        Consume(username, PasskeyCeremony.Assertion) as AssertionOptions;

    private void Hold(string username, PasskeyCeremony ceremony, object ceremonyOptions)
    {
        Sweep();

        _pending[(username, ceremony)] =
            new Entry(ceremonyOptions, clock.GetUtcNow() + _options.ChallengeLifetime);
    }

    private object? Consume(string username, PasskeyCeremony ceremony)
    {
        Sweep();

        if (!_pending.TryRemove((username, ceremony), out var entry))
        {
            return null;
        }

        return entry.ExpiresAt <= clock.GetUtcNow() ? null : entry.Options;
    }

    private void Sweep()
    {
        var now = clock.GetUtcNow();

        foreach (var (key, entry) in _pending)
        {
            if (entry.ExpiresAt <= now)
            {
                _pending.TryRemove(key, out _);
            }
        }
    }

    private sealed record Entry(object Options, DateTimeOffset ExpiresAt);
}

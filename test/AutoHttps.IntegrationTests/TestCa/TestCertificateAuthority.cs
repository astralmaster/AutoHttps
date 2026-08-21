using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AutoHttps.IntegrationTests.TestCa;

/// <summary>
/// An in-process ACME certificate authority that speaks enough of RFC 8555 and RFC 9773 to drive
/// the client through a real order: signatures are verified, nonces are single use, challenges are
/// validated by actually fetching the URL or reading the TXT record, and issued certificates are
/// signed by a real throwaway certificate authority.
/// </summary>
internal sealed class TestCertificateAuthority : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly TestCaIssuer _issuer;
    private readonly HttpClient _validationClient;

    private readonly ConcurrentDictionary<string, byte> _nonces = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, TestAccount> _accounts = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, TestOrder> _orders = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, TestAuthorization> _authorizations = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, TestChallenge> _challenges = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, TestIssuedCertificate> _certificates = new(StringComparer.Ordinal);

    private int _requestCount;
    private int _orderCount;
    private int _orderAttempts;
    private readonly ConcurrentQueue<DateTimeOffset> _orderAttemptTimes = new();

    private Uri _baseAddress = new("http://127.0.0.1/");

    private TestCertificateAuthority(WebApplication app, TestCaIssuer issuer)
    {
        _app = app;
        _issuer = issuer;
        _validationClient = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
    }

    public Uri BaseAddress => _baseAddress;

    public Uri DirectoryUri => new(BaseAddress, "directory");

    public X509Certificate2 RootCertificate => _issuer.Root;

    /// <summary>The issuing intermediate, for tests that model a client which already holds it.</summary>
    public X509Certificate2 IntermediateCertificate => _issuer.Intermediate;

    public TestCaBehavior Behavior { get; } = new();

    public TestDnsZone Dns { get; } = new();

    /// <summary>Maps a domain being validated onto the address the test application is listening on.</summary>
    public Func<string, Uri?>? HttpChallengeResolver { get; set; }

    public int RequestCount => Volatile.Read(ref _requestCount);

    public int OrderCount => Volatile.Read(ref _orderCount);

    public int OrderAttempts => Volatile.Read(ref _orderAttempts);

    public IReadOnlyList<DateTimeOffset> OrderAttemptTimes => _orderAttemptTimes.ToArray();

    public int AccountCount => _accounts.Count;

    public IReadOnlyCollection<TestIssuedCertificate> IssuedCertificates => _certificates.Values.ToArray();

    public static async Task<TestCertificateAuthority> StartAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");

        WebApplication app = builder.Build();
        var authority = new TestCertificateAuthority(app, new TestCaIssuer(DateTimeOffset.UtcNow));

        app.Use(async (context, next) =>
        {
            authority.OnRequest(context);
            await next();
        });

        authority.MapEndpoints(app);
        await app.StartAsync();

        // Every URL the authority hands out is built while a request is being served, so the real
        // address only has to be known by then. Binding to port zero removes the race that comes
        // with picking a port before the listener exists.
        string address = app.Urls.FirstOrDefault()
            ?? throw new InvalidOperationException("The test authority did not bind an address.");

        authority._baseAddress = new Uri(address.TrimEnd('/') + "/");
        return authority;
    }

    public async ValueTask DisposeAsync()
    {
        _validationClient.Dispose();
        await _app.DisposeAsync();

        foreach (TestIssuedCertificate certificate in _certificates.Values)
        {
            certificate.Leaf.Dispose();
        }

        _issuer.Dispose();
    }

    private void OnRequest(HttpContext context)
    {
        Interlocked.Increment(ref _requestCount);
        context.Response.Headers["Replay-Nonce"] = IssueNonce();
        context.Response.Headers.CacheControl = "no-store";
    }

    private void MapEndpoints(WebApplication app)
    {
        app.MapGet("/directory", GetDirectory);
        app.MapMethods("/new-nonce", ["GET", "HEAD"], (HttpContext context) =>
        {
            context.Response.StatusCode = StatusCodes.Status204NoContent;
            return Task.CompletedTask;
        });

        app.MapPost("/new-account", NewAccountAsync);
        app.MapPost("/new-order", NewOrderAsync);
        app.MapPost("/authz/{id}", (HttpContext context, string id) => AuthorizationAsync(context, id));
        app.MapPost("/challenge/{id}", (HttpContext context, string id) => ChallengeAsync(context, id));
        app.MapPost("/order/{id}", (HttpContext context, string id) => OrderAsync(context, id));
        app.MapPost("/finalize/{id}", (HttpContext context, string id) => FinalizeAsync(context, id));
        app.MapPost("/certificate/{id}", (HttpContext context, string id) => CertificateAsync(context, id));
        app.MapGet("/renewal-info/{certificateId}", (HttpContext context, string certificateId) => RenewalInfoAsync(context, certificateId));
    }

    private Task GetDirectory(HttpContext context)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("newNonce", Url("new-nonce"));
            writer.WriteString("newAccount", Url("new-account"));
            writer.WriteString("newOrder", Url("new-order"));
            writer.WriteString("revokeCert", Url("revoke-cert"));
            writer.WriteString("keyChange", Url("key-change"));

            if (Behavior.AdvertiseRenewalInfo)
            {
                writer.WriteString("renewalInfo", Url("renewal-info"));
            }

            writer.WriteStartObject("meta");
            writer.WriteString("termsOfService", Url("terms"));
            writer.WriteString("website", BaseAddress.AbsoluteUri);

            if (Behavior.RequireExternalAccountBinding)
            {
                writer.WriteBoolean("externalAccountRequired", true);
            }

            if (Behavior.AdvertiseProfiles)
            {
                writer.WriteStartObject("profiles");
                writer.WriteString(CertificateProfiles.Classic, "90 day certificates");
                writer.WriteString(CertificateProfiles.TlsServer, "45 day certificates");
                writer.WriteString(CertificateProfiles.ShortLived, "6 day certificates");
                writer.WriteEndObject();
            }

            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        return WriteJsonAsync(context, StatusCodes.Status200OK, buffer.ToArray());
    }

    private async Task NewAccountAsync(HttpContext context)
    {
        if (await ShouldInterruptAsync(context))
        {
            return;
        }

        VerifiedRequest request;
        try
        {
            request = await ReadRequestAsync(context);
        }
        catch (JwsVerificationException ex)
        {
            await WriteProblemAsync(context, StatusCodes.Status400BadRequest, ex.ErrorType, ex.Message);
            return;
        }

        if (request.Jwk is not { } jwk)
        {
            await WriteProblemAsync(context, StatusCodes.Status400BadRequest, "urn:ietf:params:acme:error:malformed", "newAccount must be signed with a jwk.");
            return;
        }

        using JsonDocument payload = JsonDocument.Parse(request.Payload.Length == 0 ? "{}" : request.Payload);
        JsonElement root = payload.RootElement;

        if (!root.TryGetProperty("termsOfServiceAgreed", out JsonElement agreed) || !agreed.GetBoolean())
        {
            await WriteProblemAsync(
                context,
                StatusCodes.Status400BadRequest,
                "urn:ietf:params:acme:error:userActionRequired",
                "The subscriber agreement must be accepted.");
            return;
        }

        if (Behavior.RequireExternalAccountBinding && !await ValidateExternalAccountBindingAsync(context, root, jwk))
        {
            return;
        }

        string thumbprint = TestJws.Thumbprint(jwk);
        TestAccount? existing = _accounts.Values.FirstOrDefault(a => a.Thumbprint == thumbprint);

        if (existing is not null)
        {
            context.Response.Headers.Location = Url("account/" + existing.Id);
            await WriteJsonAsync(context, StatusCodes.Status200OK, SerializeAccount(existing));
            return;
        }

        var account = new TestAccount
        {
            Id = NewId(),
            Jwk = jwk,
            Thumbprint = thumbprint,
        };

        if (root.TryGetProperty("contact", out JsonElement contacts) && contacts.ValueKind == JsonValueKind.Array)
        {
            account.Contacts.AddRange(contacts.EnumerateArray().Select(c => c.GetString() ?? string.Empty));
        }

        _accounts[account.Id] = account;

        if (Behavior.FailNextAccountResponsesCount > 0)
        {
            Behavior.FailNextAccountResponsesCount--;
            await WriteProblemAsync(
                context,
                StatusCodes.Status400BadRequest,
                "urn:ietf:params:acme:error:malformed",
                "The account was registered but the response was lost.");
            return;
        }

        context.Response.Headers.Location = Url("account/" + account.Id);
        await WriteJsonAsync(context, StatusCodes.Status201Created, SerializeAccount(account));
    }

    private async Task<bool> ValidateExternalAccountBindingAsync(HttpContext context, JsonElement payload, JsonElement accountJwk)
    {
        if (!payload.TryGetProperty("externalAccountBinding", out JsonElement binding))
        {
            await WriteProblemAsync(
                context,
                StatusCodes.Status400BadRequest,
                "urn:ietf:params:acme:error:externalAccountRequired",
                "This certificate authority requires an external account binding.");
            return false;
        }

        if (Behavior.ExternalAccountHmacKey is not { } key ||
            !TestJws.VerifyHmac(key, binding.GetRawText(), out string inner) ||
            !string.Equals(NormalizeJson(inner), NormalizeJson(TestJws.Canonicalize(accountJwk)), StringComparison.Ordinal))
        {
            await WriteProblemAsync(
                context,
                StatusCodes.Status400BadRequest,
                "urn:ietf:params:acme:error:malformed",
                "The external account binding is not valid.");
            return false;
        }

        return true;
    }

    private async Task NewOrderAsync(HttpContext context)
    {
        if (await ShouldInterruptAsync(context))
        {
            return;
        }

        if (Volatile.Read(ref _orderCount) >= Behavior.ForgetAccountsAfterOrders)
        {
            // Forgetting once models an account being deactivated or lost. The authority still
            // accepts a fresh registration afterwards, which is what the client has to do.
            Behavior.ForgetAccountsAfterOrders = int.MaxValue;
            _accounts.Clear();
        }

        Interlocked.Increment(ref _orderAttempts);
        _orderAttemptTimes.Enqueue(DateTimeOffset.UtcNow);

        if (Behavior.RateLimitNextOrdersCount > 0)
        {
            Behavior.RateLimitNextOrdersCount--;

            if (Behavior.RateLimitRetryAfter is { } retryAfter)
            {
                context.Response.Headers.RetryAfter = ((int)retryAfter.TotalSeconds).ToString(CultureInfo.InvariantCulture);
            }

            await WriteProblemAsync(
                context,
                StatusCodes.Status429TooManyRequests,
                "urn:ietf:params:acme:error:rateLimited",
                "Too many certificates already issued.");
            return;
        }

        VerifiedRequest request;
        TestAccount account;
        try
        {
            request = await ReadRequestAsync(context);
            account = RequireAccount(request);
        }
        catch (JwsVerificationException ex)
        {
            await WriteProblemAsync(context, StatusCodes.Status400BadRequest, ex.ErrorType, ex.Message);
            return;
        }

        using JsonDocument payload = JsonDocument.Parse(request.Payload);
        JsonElement root = payload.RootElement;

        var identifiers = new List<TestIdentifier>();
        foreach (JsonElement identifier in root.GetProperty("identifiers").EnumerateArray())
        {
            identifiers.Add(new TestIdentifier(
                identifier.GetProperty("type").GetString() ?? "dns",
                identifier.GetProperty("value").GetString() ?? string.Empty));
        }

        string? profile = root.TryGetProperty("profile", out JsonElement profileElement) ? profileElement.GetString() : null;
        string? replaces = root.TryGetProperty("replaces", out JsonElement replacesElement) ? replacesElement.GetString() : null;

        if (profile is not null && Behavior.AdvertiseProfiles &&
            profile is not (CertificateProfiles.Classic or CertificateProfiles.TlsServer or CertificateProfiles.ShortLived))
        {
            await WriteProblemAsync(
                context,
                StatusCodes.Status400BadRequest,
                "urn:ietf:params:acme:error:invalidProfile",
                $"Unknown profile '{profile}'.");
            return;
        }

        var order = new TestOrder
        {
            Id = NewId(),
            AccountId = account.Id,
            Identifiers = identifiers,
            Profile = profile,
            Replaces = replaces,
            Expires = DateTimeOffset.UtcNow.AddDays(7),
        };

        foreach (TestIdentifier identifier in identifiers)
        {
            if (Behavior.ReuseValidAuthorizations &&
                _authorizations.Values.FirstOrDefault(a => a.Status == "valid" && a.Identifier == identifier) is { } reused)
            {
                order.AuthorizationIds.Add(reused.Id);
                continue;
            }

            var authorization = new TestAuthorization
            {
                Id = NewId(),
                OrderId = order.Id,
                Identifier = identifier,
            };

            if (identifier.IsWildcard)
            {
                authorization.Challenges.Add(CreateChallenge(authorization.Id, "dns-01"));
            }
            else
            {
                authorization.Challenges.Add(CreateChallenge(authorization.Id, "http-01"));
                authorization.Challenges.Add(CreateChallenge(authorization.Id, "dns-01"));
            }

            _authorizations[authorization.Id] = authorization;
            order.AuthorizationIds.Add(authorization.Id);
        }

        _orders[order.Id] = order;
        Interlocked.Increment(ref _orderCount);

        context.Response.Headers.Location = Url("order/" + order.Id);
        await WriteJsonAsync(context, StatusCodes.Status201Created, SerializeOrder(order));
    }

    private TestChallenge CreateChallenge(string authorizationId, string type)
    {
        var challenge = new TestChallenge
        {
            Id = NewId(),
            AuthorizationId = authorizationId,
            Type = type,
            Token = TestJws.Encode(RandomNumberGenerator.GetBytes(32)),
        };

        _challenges[challenge.Id] = challenge;
        return challenge;
    }

    private async Task AuthorizationAsync(HttpContext context, string id)
    {
        if (await ShouldInterruptAsync(context))
        {
            return;
        }

        try
        {
            VerifiedRequest request = await ReadRequestAsync(context);
            RequireAccount(request);
        }
        catch (JwsVerificationException ex)
        {
            await WriteProblemAsync(context, StatusCodes.Status400BadRequest, ex.ErrorType, ex.Message);
            return;
        }

        if (!_authorizations.TryGetValue(id, out TestAuthorization? authorization))
        {
            await WriteProblemAsync(context, StatusCodes.Status404NotFound, "urn:ietf:params:acme:error:malformed", "Unknown authorization.");
            return;
        }

        AdvanceAuthorization(authorization);
        await WriteJsonAsync(context, StatusCodes.Status200OK, SerializeAuthorization(authorization));
    }

    private void AdvanceAuthorization(TestAuthorization authorization)
    {
        if (authorization.Status != "pending" || !authorization.ValidationAttempted)
        {
            return;
        }

        authorization.Polls++;

        if (authorization.Polls <= Behavior.PollsBeforeAuthorizationValid)
        {
            return;
        }

        if (authorization.ValidationSucceeded)
        {
            authorization.Status = "valid";
            foreach (TestChallenge challenge in authorization.Challenges)
            {
                if (challenge.Status == "processing")
                {
                    challenge.Status = "valid";
                }
            }
        }
        else
        {
            authorization.Status = "invalid";
            foreach (TestChallenge challenge in authorization.Challenges)
            {
                if (challenge.Status == "processing")
                {
                    challenge.Status = "invalid";
                }
            }
        }
    }

    private async Task ChallengeAsync(HttpContext context, string id)
    {
        if (await ShouldInterruptAsync(context))
        {
            return;
        }

        TestAccount account;
        try
        {
            VerifiedRequest request = await ReadRequestAsync(context);
            account = RequireAccount(request);
        }
        catch (JwsVerificationException ex)
        {
            await WriteProblemAsync(context, StatusCodes.Status400BadRequest, ex.ErrorType, ex.Message);
            return;
        }

        if (!_challenges.TryGetValue(id, out TestChallenge? challenge) ||
            !_authorizations.TryGetValue(challenge.AuthorizationId, out TestAuthorization? authorization))
        {
            await WriteProblemAsync(context, StatusCodes.Status404NotFound, "urn:ietf:params:acme:error:malformed", "Unknown challenge.");
            return;
        }

        challenge.Status = "processing";
        authorization.ValidationAttempted = true;
        authorization.ValidationSucceeded = !Behavior.FailValidation && await ValidateAsync(account, authorization, challenge);

        if (!authorization.ValidationSucceeded)
        {
            authorization.ErrorType = Behavior.ValidationErrorType;
            authorization.ErrorDetail = $"The {challenge.Type} challenge for '{authorization.Identifier.Value}' did not validate.";
        }

        await WriteJsonAsync(context, StatusCodes.Status200OK, SerializeChallenge(authorization, challenge));
    }

    private async Task<bool> ValidateAsync(TestAccount account, TestAuthorization authorization, TestChallenge challenge)
    {
        string keyAuthorization = challenge.Token + "." + account.Thumbprint;

        if (challenge.Type == "dns-01")
        {
            string expected = TestJws.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(keyAuthorization)));
            return Dns.Contains("_acme-challenge." + authorization.Identifier.BaseValue, expected);
        }

        if (HttpChallengeResolver?.Invoke(authorization.Identifier.Value) is not { } target)
        {
            return false;
        }

        try
        {
            var url = new Uri(target, $"/.well-known/acme-challenge/{challenge.Token}");
            using HttpResponseMessage response = await _validationClient.GetAsync(url);

            if (!response.IsSuccessStatusCode)
            {
                return false;
            }

            string body = (await response.Content.ReadAsStringAsync()).Trim();
            return string.Equals(body, keyAuthorization, StringComparison.Ordinal);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return false;
        }
    }

    private async Task OrderAsync(HttpContext context, string id)
    {
        if (await ShouldInterruptAsync(context))
        {
            return;
        }

        try
        {
            VerifiedRequest request = await ReadRequestAsync(context);
            RequireAccount(request);
        }
        catch (JwsVerificationException ex)
        {
            await WriteProblemAsync(context, StatusCodes.Status400BadRequest, ex.ErrorType, ex.Message);
            return;
        }

        if (!_orders.TryGetValue(id, out TestOrder? order))
        {
            await WriteProblemAsync(context, StatusCodes.Status404NotFound, "urn:ietf:params:acme:error:malformed", "Unknown order.");
            return;
        }

        RefreshOrderStatus(order);
        await WriteJsonAsync(context, StatusCodes.Status200OK, SerializeOrder(order));
    }

    private void RefreshOrderStatus(TestOrder order)
    {
        if (order.Status is "valid" or "invalid")
        {
            return;
        }

        var authorizations = order.AuthorizationIds.Select(a => _authorizations[a]).ToArray();

        foreach (TestAuthorization authorization in authorizations)
        {
            AdvanceAuthorization(authorization);
        }

        if (authorizations.Any(a => a.Status == "invalid"))
        {
            order.Status = "invalid";
            order.ErrorType = "urn:ietf:params:acme:error:unauthorized";
            order.ErrorDetail = authorizations.First(a => a.Status == "invalid").ErrorDetail;
        }
        else if (order.Status == "pending" && authorizations.All(a => a.Status == "valid"))
        {
            order.Status = "ready";
        }
    }

    private async Task FinalizeAsync(HttpContext context, string id)
    {
        if (await ShouldInterruptAsync(context))
        {
            return;
        }

        VerifiedRequest request;
        try
        {
            request = await ReadRequestAsync(context);
            RequireAccount(request);
        }
        catch (JwsVerificationException ex)
        {
            await WriteProblemAsync(context, StatusCodes.Status400BadRequest, ex.ErrorType, ex.Message);
            return;
        }

        if (!_orders.TryGetValue(id, out TestOrder? order))
        {
            await WriteProblemAsync(context, StatusCodes.Status404NotFound, "urn:ietf:params:acme:error:malformed", "Unknown order.");
            return;
        }

        if (Behavior.RejectNextFinalizeCount > 0)
        {
            Behavior.RejectNextFinalizeCount--;
            await WriteProblemAsync(
                context,
                StatusCodes.Status500InternalServerError,
                "urn:ietf:params:acme:error:serverInternal",
                "The issuance pipeline is unavailable.");
            return;
        }

        RefreshOrderStatus(order);

        if (order.Status != "ready")
        {
            await WriteProblemAsync(
                context,
                StatusCodes.Status403Forbidden,
                "urn:ietf:params:acme:error:orderNotReady",
                $"The order is '{order.Status}' and cannot be finalized.");
            return;
        }

        using JsonDocument payload = JsonDocument.Parse(request.Payload);
        byte[] signingRequest = TestJws.Decode(payload.RootElement.GetProperty("csr").GetString()!);

        var requested = _issuer.ReadSubjectAlternativeNames(signingRequest).ToArray();
        var expected = order.Identifiers.Select(i => i.Value).ToArray();

        if (requested.Length != expected.Length ||
            !expected.All(e => requested.Contains(e, StringComparer.OrdinalIgnoreCase)))
        {
            await WriteProblemAsync(
                context,
                StatusCodes.Status400BadRequest,
                "urn:ietf:params:acme:error:badCSR",
                $"The certificate signing request covers [{string.Join(", ", requested)}] but the order covers [{string.Join(", ", expected)}].");
            return;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        TimeSpan lifetime = order.Profile == CertificateProfiles.ShortLived
            ? TimeSpan.FromHours(160)
            : Behavior.CertificateLifetime;

        DateTimeOffset notBefore = now.AddSeconds(-5) + Behavior.NotBeforeSkew;
        X509Certificate2 leaf = _issuer.Issue(signingRequest, notBefore, notBefore + lifetime);

        var issued = new TestIssuedCertificate
        {
            Id = NewId(),
            ChainPem = _issuer.BuildChainPem(leaf),
            Leaf = leaf,
            SubjectNames = requested,
            Profile = order.Profile,
            Replaces = order.Replaces,
        };

        _certificates[issued.Id] = issued;
        order.CertificateId = issued.Id;
        order.Status = "valid";

        context.Response.Headers.Location = Url("order/" + order.Id);
        await WriteJsonAsync(context, StatusCodes.Status200OK, SerializeOrder(order));
    }

    private async Task CertificateAsync(HttpContext context, string id)
    {
        if (await ShouldInterruptAsync(context))
        {
            return;
        }

        try
        {
            VerifiedRequest request = await ReadRequestAsync(context);
            RequireAccount(request);
        }
        catch (JwsVerificationException ex)
        {
            await WriteProblemAsync(context, StatusCodes.Status400BadRequest, ex.ErrorType, ex.Message);
            return;
        }

        if (!_certificates.TryGetValue(id, out TestIssuedCertificate? certificate))
        {
            await WriteProblemAsync(context, StatusCodes.Status404NotFound, "urn:ietf:params:acme:error:malformed", "Unknown certificate.");
            return;
        }

        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "application/pem-certificate-chain";
        await context.Response.WriteAsync(certificate.ChainPem);
    }

    private async Task RenewalInfoAsync(HttpContext context, string certificateId)
    {
        TestIssuedCertificate? certificate = _certificates.Values
            .FirstOrDefault(c => ComputeCertificateId(c.Leaf) == certificateId);

        if (certificate is null)
        {
            await WriteProblemAsync(context, StatusCodes.Status404NotFound, "urn:ietf:params:acme:error:malformed", "Unknown certificate.");
            return;
        }

        (DateTimeOffset start, DateTimeOffset end) = Behavior.RenewalWindowFactory?.Invoke(certificate.Leaf)
            ?? DefaultWindow(certificate.Leaf);

        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteStartObject("suggestedWindow");
            writer.WriteString("start", start);
            writer.WriteString("end", end);
            writer.WriteEndObject();
            writer.WriteString("explanationURL", Url("explain"));
            writer.WriteEndObject();
        }

        context.Response.Headers.RetryAfter = "21600";
        await WriteJsonAsync(context, StatusCodes.Status200OK, buffer.ToArray());
    }

    private static (DateTimeOffset Start, DateTimeOffset End) DefaultWindow(X509Certificate2 certificate)
    {
        DateTimeOffset notBefore = new(certificate.NotBefore.ToUniversalTime(), TimeSpan.Zero);
        DateTimeOffset notAfter = new(certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero);
        TimeSpan lifetime = notAfter - notBefore;

        return (notAfter - (lifetime / 3), notAfter - (lifetime / 6));
    }

    public static string ComputeCertificateId(X509Certificate2 certificate)
    {
        X509Extension extension = certificate.Extensions["2.5.29.35"]
            ?? throw new InvalidOperationException("The certificate has no authority key identifier.");

        var authorityKeyIdentifier = new X509AuthorityKeyIdentifierExtension(extension.RawData, extension.Critical);
        ReadOnlyMemory<byte> keyIdentifier = authorityKeyIdentifier.KeyIdentifier
            ?? throw new InvalidOperationException("The authority key identifier has no key id.");

        byte[] serial = certificate.GetSerialNumber();
        Array.Reverse(serial);

        return TestJws.Encode(keyIdentifier.Span) + "." + TestJws.Encode(serial);
    }

    private async Task<bool> ShouldInterruptAsync(HttpContext context)
    {
        if (Behavior.ReturnHtmlForNextRequests > 0)
        {
            Behavior.ReturnHtmlForNextRequests--;
            context.Response.StatusCode = StatusCodes.Status502BadGateway;
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync(
                "<html><head><title>502 Bad Gateway</title></head><body><h1>Bad Gateway</h1></body></html>");
            return true;
        }

        if (Behavior.FailNextRequestsWith503Count > 0)
        {
            Behavior.FailNextRequestsWith503Count--;
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            await context.Response.WriteAsync("busy");
            return true;
        }

        return false;
    }

    private async Task<VerifiedRequest> ReadRequestAsync(HttpContext context)
    {
        // Real authorities compare these headers as exact strings. Boulder rejects a POST whose
        // content type carries a charset parameter, and every request without a user agent.
        string contentType = context.Request.Headers.ContentType.ToString();
        if (!string.Equals(contentType, "application/jose+json", StringComparison.Ordinal))
        {
            throw new JwsVerificationException(
                $"Content-Type must be exactly \"application/jose+json\" but was \"{contentType}\".");
        }

        if (string.IsNullOrEmpty(context.Request.Headers.UserAgent.ToString()))
        {
            throw new JwsVerificationException("All requests must include a User-Agent header.");
        }

        using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
        string body = await reader.ReadToEndAsync();

        var url = new Uri(BaseAddress, context.Request.Path.Value!.TrimStart('/'));
        VerifiedRequest request = TestJws.Verify(body, url, ResolveAccountKey);

        if (!_nonces.TryRemove(request.Nonce, out _))
        {
            throw new JwsVerificationException("The nonce is unknown or has already been used.", "urn:ietf:params:acme:error:badNonce");
        }

        if (Behavior.RejectNextNoncesCount > 0)
        {
            Behavior.RejectNextNoncesCount--;
            throw new JwsVerificationException("The nonce was rejected.", "urn:ietf:params:acme:error:badNonce");
        }

        return request;
    }

    private JsonElement? ResolveAccountKey(string keyId)
    {
        string id = keyId[(keyId.LastIndexOf('/') + 1)..];
        return _accounts.TryGetValue(id, out TestAccount? account) ? account.Jwk : null;
    }

    private TestAccount RequireAccount(VerifiedRequest request)
    {
        if (request.KeyId is null)
        {
            throw new JwsVerificationException("This request must be signed with a kid.");
        }

        string id = request.KeyId[(request.KeyId.LastIndexOf('/') + 1)..];
        return _accounts.TryGetValue(id, out TestAccount? account)
            ? account
            : throw new JwsVerificationException("Unknown account.", "urn:ietf:params:acme:error:accountDoesNotExist");
    }

    private byte[] SerializeAccount(TestAccount account)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("status", "valid");
            writer.WriteStartArray("contact");
            foreach (string contact in account.Contacts)
            {
                writer.WriteStringValue(contact);
            }

            writer.WriteEndArray();
            writer.WriteString("orders", Url("account/" + account.Id + "/orders"));
            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    private byte[] SerializeOrder(TestOrder order)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("status", order.Status);
            writer.WriteString("expires", order.Expires);

            writer.WriteStartArray("identifiers");
            foreach (TestIdentifier identifier in order.Identifiers)
            {
                writer.WriteStartObject();
                writer.WriteString("type", identifier.Type);
                writer.WriteString("value", identifier.Value);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();

            writer.WriteStartArray("authorizations");
            foreach (string authorizationId in order.AuthorizationIds)
            {
                writer.WriteStringValue(Url("authz/" + authorizationId));
            }

            writer.WriteEndArray();
            writer.WriteString("finalize", Url("finalize/" + order.Id));

            if (order.CertificateId is not null)
            {
                writer.WriteString("certificate", Url("certificate/" + order.CertificateId));
            }

            if (order.ErrorType is not null)
            {
                writer.WriteStartObject("error");
                writer.WriteString("type", order.ErrorType);
                writer.WriteString("detail", order.ErrorDetail);
                writer.WriteEndObject();
            }

            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    private byte[] SerializeAuthorization(TestAuthorization authorization)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteStartObject("identifier");
            writer.WriteString("type", authorization.Identifier.Type);
            writer.WriteString("value", authorization.Identifier.BaseValue);
            writer.WriteEndObject();

            writer.WriteString("status", authorization.Status);

            if (authorization.Identifier.IsWildcard)
            {
                writer.WriteBoolean("wildcard", true);
            }

            writer.WriteStartArray("challenges");
            foreach (TestChallenge challenge in authorization.Challenges)
            {
                WriteChallenge(writer, authorization, challenge);
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    private byte[] SerializeChallenge(TestAuthorization authorization, TestChallenge challenge)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            WriteChallenge(writer, authorization, challenge);
        }

        return buffer.ToArray();
    }

    private void WriteChallenge(Utf8JsonWriter writer, TestAuthorization authorization, TestChallenge challenge)
    {
        writer.WriteStartObject();
        writer.WriteString("type", challenge.Type);
        writer.WriteString("url", Url("challenge/" + challenge.Id));
        writer.WriteString("status", challenge.Status);
        writer.WriteString("token", challenge.Token);

        if (challenge.Status == "invalid" && authorization.ErrorType is not null)
        {
            writer.WriteStartObject("error");
            writer.WriteString("type", authorization.ErrorType);
            writer.WriteString("detail", authorization.ErrorDetail);
            writer.WriteEndObject();
        }

        writer.WriteEndObject();
    }

    private static Task WriteJsonAsync(HttpContext context, int statusCode, byte[] json)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";
        return context.Response.Body.WriteAsync(json, 0, json.Length);
    }

    private static Task WriteProblemAsync(HttpContext context, int statusCode, string type, string detail)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("type", type);
            writer.WriteString("detail", detail);
            writer.WriteNumber("status", statusCode);
            writer.WriteEndObject();
        }

        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/problem+json";
        byte[] json = buffer.ToArray();
        return context.Response.Body.WriteAsync(json, 0, json.Length);
    }

    private static string NormalizeJson(string json)
    {
        using JsonDocument document = JsonDocument.Parse(json);
        return document.RootElement.GetRawText().Replace(" ", string.Empty).Replace("\n", string.Empty).Replace("\r", string.Empty);
    }

    private string IssueNonce()
    {
        string nonce = TestJws.Encode(RandomNumberGenerator.GetBytes(16));
        _nonces[nonce] = 0;
        return nonce;
    }

    private string Url(string path) => new Uri(BaseAddress, path).AbsoluteUri;

    private static string NewId() => TestJws.Encode(RandomNumberGenerator.GetBytes(12));
}

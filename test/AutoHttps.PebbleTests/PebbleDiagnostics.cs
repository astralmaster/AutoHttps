using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Acme;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Xunit.Abstractions;

namespace AutoHttps.PebbleTests;

/// <summary>
/// Drives the protocol layer against Pebble directly, so a rejected request reports the authority's
/// own explanation instead of only the timeout that follows it.
/// </summary>
[Collection(PebbleCollection.Name)]
public class PebbleDiagnostics
{
    private readonly PebbleFixture _pebble;
    private readonly ITestOutputHelper _output;

    public PebbleDiagnostics(PebbleFixture pebble, ITestOutputHelper output)
    {
        _pebble = pebble;
        _output = output;
    }

    [Fact]
    public async Task TheDirectoryAndAccountRegistrationSucceed()
    {
        var http = new AcmeHttpClient(
            new SingleHandlerFactory(_pebble.CreateAcmeHandler()),
            "pebble",
            _pebble.DirectoryUri,
            NullLogger.Instance,
            TimeProvider.System);

        AcmeDirectory directory = await http.GetDirectoryAsync(CancellationToken.None);
        _output.WriteLine($"newAccount   = {directory.NewAccount}");
        _output.WriteLine($"newOrder     = {directory.NewOrder}");
        _output.WriteLine($"renewalInfo  = {directory.RenewalInfo}");
        _output.WriteLine($"profiles     = {string.Join(", ", directory.Meta?.Profiles?.Keys ?? [])}");

        using var key = AcmeKey.CreateEcdsa();
        var client = new AcmeClient(http, key, NullLogger.Instance, TimeProvider.System);

        try
        {
            string accountUrl = await client.RegisterAccountAsync(
                ["mailto:operator@example.com"],
                termsOfServiceAgreed: true,
                externalAccountBinding: null,
                CancellationToken.None);

            _output.WriteLine($"account      = {accountUrl}");
            Assert.NotEmpty(accountUrl);
        }
        catch (AcmeException ex)
        {
            _output.WriteLine($"REGISTRATION FAILED: {ex.Message}");
            _output.WriteLine($"  errorType = {ex.ErrorType}");
            _output.WriteLine($"  detail    = {ex.Detail}");
            _output.WriteLine($"  status    = {ex.StatusCode}");
            _output.WriteLine($"  inner     = {ex.InnerException?.Message}");
            throw;
        }
    }

    private sealed class SingleHandlerFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;

        public SingleHandlerFactory(HttpMessageHandler handler) => _handler = handler;

        public HttpClient CreateClient(string name)
        {
            var client = new HttpClient(_handler, disposeHandler: false);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("AutoHttps.PebbleTests/1.0");

            return client;
        }
    }
}

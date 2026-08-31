using System;
using System.Collections.Generic;
using System.Net;

namespace AutoHttps.Acme;

internal sealed class AcmeResponse<T>
{
    public AcmeResponse(
        HttpStatusCode statusCode,
        T? content,
        Uri? location,
        IReadOnlyList<AcmeLink> links,
        string rawBody,
        DateTimeOffset? retryAfter = null)
    {
        StatusCode = statusCode;
        Content = content;
        Location = location;
        Links = links;
        RawBody = rawBody;
        RetryAfter = retryAfter;
    }

    public HttpStatusCode StatusCode { get; }

    public T? Content { get; }

    public Uri? Location { get; }

    public IReadOnlyList<AcmeLink> Links { get; }

    public string RawBody { get; }

    /// <summary>When the authority returned a Retry-After header, the moment it asked to be polled again.</summary>
    public DateTimeOffset? RetryAfter { get; }
}

internal readonly record struct AcmeLink(Uri Url, string Relation);

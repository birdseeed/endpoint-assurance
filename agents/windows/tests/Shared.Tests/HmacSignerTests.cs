using System;
using System.Text;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Shared.Tests;

public sealed class HmacSignerTests
{
    private static readonly string TestBase64Secret = Convert.ToBase64String(Encoding.ASCII.GetBytes("patched-test-secret"));
    private const string Ts = "1730000000";
    private const string Nonce = "abc123nonce";
    private const string Body = "{\"hello\":\"world\"}";
    private const string InventoryV3Vector = "e4825ff7d3d56103fb9904615eebb2a317cef582256f066a443bc66974cd75d4";
    private const string AgentConfigV3Vector = "868b6e53c5c2ba9cbf72d0af25e06157eed1fff7ca68148412c2dd0952295d3f";

    [Fact]
    public void ComputeSignature_MatchesAuthoritativeVectors()
    {
        Assert.Equal(InventoryV3Vector, HmacSigner.ComputeSignature(TestBase64Secret, "POST", HmacSigner.EndpointInventory, Ts, Nonce, Encoding.UTF8.GetBytes(Body)));
        Assert.Equal(AgentConfigV3Vector, HmacSigner.ComputeSignature(TestBase64Secret, "GET", HmacSigner.EndpointAgentConfig, Ts, Nonce, ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void VerifySignature_RejectsCrossEndpointAndMethodReuse()
    {
        var body = Encoding.UTF8.GetBytes(Body);
        Assert.False(HmacSigner.VerifySignature(TestBase64Secret, "POST", HmacSigner.EndpointProvenance, Ts, Nonce, body, InventoryV3Vector));
        Assert.False(HmacSigner.VerifySignature(TestBase64Secret, "GET", HmacSigner.EndpointInventory, Ts, Nonce, body, InventoryV3Vector));
    }

    [Fact]
    public void ComputeSignature_BindsTimestampNonceAndBody()
    {
        var body = Encoding.UTF8.GetBytes(Body);
        var signature = HmacSigner.ComputeSignature(TestBase64Secret, "POST", HmacSigner.EndpointInventory, Ts, Nonce, body);
        Assert.NotEqual(signature, HmacSigner.ComputeSignature(TestBase64Secret, "POST", HmacSigner.EndpointInventory, "1730000001", Nonce, body));
        Assert.NotEqual(signature, HmacSigner.ComputeSignature(TestBase64Secret, "POST", HmacSigner.EndpointInventory, Ts, "different-nonce", body));
        Assert.NotEqual(signature, HmacSigner.ComputeSignature(TestBase64Secret, "POST", HmacSigner.EndpointInventory, Ts, Nonce, Encoding.UTF8.GetBytes(Body + "x")));
    }
}

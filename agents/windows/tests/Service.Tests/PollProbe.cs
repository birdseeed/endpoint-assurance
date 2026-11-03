using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-2423: counts the poll cycles of a wait loop, so a test can let the loop run a
/// known number of them and then cancel it, instead of cancelling on a wall-clock
/// timeout and hoping enough cycles ran first.
///
/// The recovery and provisioning waits take no clock: they sleep with Task.Delay and
/// re-read a source the test supplies (CredentialStore.CreateForTests'
/// enrollmentTokenSource or provisioningSource) once per cycle. Calling
/// <see cref="Record"/> from that source counts the cycles. Tests that raced a
/// 60-250 ms CancellationTokenSource against those cycles failed on a slow runner when
/// the timeout fired before the first cycle (CI, windows-latest: 0 requests where 1
/// was expected), and their "nothing was sent" assertions passed without the loop
/// having polled at all.
/// </summary>
internal sealed class PollProbe
{
    /// <summary>
    /// Only bounds a wait loop that has stopped polling, so the test fails instead of
    /// hanging. It is not part of any test's timing.
    /// </summary>
    private static readonly TimeSpan HangGuard = TimeSpan.FromSeconds(60);

    private readonly object _gate = new();
    private int _count;
    private int _target;
    private TaskCompletionSource? _reached;

    public int Count
    {
        get { lock (_gate) return _count; }
    }

    /// <summary>Call from the source the wait loop re-reads. Returns the new count (1-based).</summary>
    public int Record()
    {
        TaskCompletionSource? reached = null;
        int count;
        lock (_gate)
        {
            count = ++_count;
            if (_reached is not null && count >= _target)
            {
                reached = _reached;
                _reached = null;
            }
        }
        reached?.TrySetResult();
        return count;
    }

    private Task ReachedAsync(int target)
    {
        lock (_gate)
        {
            if (_count >= target)
                return Task.CompletedTask;
            _target = target;
            _reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            return _reached.Task;
        }
    }

    /// <summary>
    /// Starts <paramref name="wait"/>, lets it run until the source has been read
    /// <paramref name="polls"/> more times, then cancels it and asserts it was still
    /// waiting (it ends with OperationCanceledException).
    ///
    /// A cycle awaits everything it starts before the next read, so when read number
    /// n + 1 happens, cycle n has finished: every request it was going to send is
    /// already counted. Fails if the wait returns or throws before the cycles are
    /// done, or if it stops polling.
    /// </summary>
    public async Task AssertStillWaitingAfterAsync(int polls, Func<CancellationToken, Task> wait)
    {
        using var cts = new CancellationTokenSource();
        var reached = ReachedAsync(Count + polls);
        var waiting = wait(cts.Token);
        try
        {
            var first = await Task.WhenAny(waiting, reached, Task.Delay(HangGuard));
            if (first == waiting)
            {
                await waiting; // surfaces the wait's own exception, if it threw
                Assert.Fail($"the wait returned after {Count} poll(s) instead of still waiting");
            }
            Assert.True(first == reached,
                $"the wait stopped polling: {Count} poll(s) in {HangGuard.TotalSeconds:0} s, expected {polls} more");
        }
        finally
        {
            cts.Cancel();
        }

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
    }
}

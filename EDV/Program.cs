using System;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics.Eventing.Reader;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Linq;
using System.Net.Http;
using System.Windows.Forms;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;

public static class Globals
{
    public static readonly int TOTAL_CONCURRENT_REQUESTS = 5;
    public static List<int> eventIds;
    public static string conversationId;
    public static readonly string _baseDomain = "copilot.microsoft.com";
    public static List<SysmonEvent> _recentSysmonEvents = new List<SysmonEvent>();
    public static List<int> _recordIds = new List<int>();
    public static readonly object _recordIdsLock = new object();
    public static readonly int queryOnlyForLastEventsInMinutes = -3;
    public static readonly string WebSocketUrl = $"wss://{Globals._baseDomain}/c/api/chat?api-version=2&dpwa=1";
    public static bool firstRun = true;
    public static DateTime initialTime;
}

public abstract class WebSocketEvent
{
    [JsonPropertyName("event")]
    public string Event { get; set; }

    [JsonPropertyName("id")]
    public string Id { get; set; }
}

public class AppendTextEvent : WebSocketEvent
{
    [JsonPropertyName("messageId")]
    public string MessageId { get; set; }

    [JsonPropertyName("partId")]
    public string PartId { get; set; }

    [JsonPropertyName("text")]
    public string Text { get; set; }
}

public class SysmonEvent
{
    public DateTime? TimeCreated { get; set; }
    public DateTime? EntryAddedAt { get; set; }
    public int EventId { get; set; }
    public int RecordId { get; set; }
    public string RawXml { get; set; }
    public bool Sent { get; set; }
    public bool Error { get; set; }
}

class Utils
{
    public static void RemoveOldEvents()
    {
        var eventsToRemove = Globals._recentSysmonEvents.Where(e => e.EntryAddedAt.HasValue && e.EntryAddedAt.Value.ToUniversalTime() < DateTime.UtcNow.AddMinutes(Globals.queryOnlyForLastEventsInMinutes - 10)).ToList();
        foreach (var e in eventsToRemove)
        {
            lock (Globals._recordIdsLock)
            {
                Globals._recordIds.Remove(e.RecordId);
                Globals._recentSysmonEvents.Remove(e);
            }
        }
    }
}

public class SyncExecutor
{
    private static ClientWebSocket _webSocket = new ClientWebSocket();
    private static readonly TimeSpan ReconnectDelay = TimeSpan.FromSeconds(5);
    private static SysmonEvent currentSysmonEvent = null;

    static List<SysmonEvent> GetEvents()
    {
        List<SysmonEvent> eventArray = new List<SysmonEvent>();
        DateTime endTime = DateTime.UtcNow;
        DateTime startTime = endTime;
        if (Globals.firstRun)
        {
            Globals.initialTime = startTime;
            Globals.firstRun = false;
        }
        else
        {
            startTime = endTime.AddMinutes(Globals.queryOnlyForLastEventsInMinutes); // get last 3 minutes ones
            if (startTime < Globals.initialTime)
            {
                startTime = Globals.initialTime;
            }
        }
        string query = $"*[System[TimeCreated[@SystemTime>='{startTime.ToUniversalTime():s}Z' and @SystemTime<='{endTime.ToUniversalTime():s}Z']]]";

        try
        {
            EventLogQuery eventQuery = new EventLogQuery("Microsoft-Windows-Sysmon/Operational", PathType.LogName, query);
            using (EventLogReader logReader = new EventLogReader(eventQuery))
            {
                int eventCount = 0;
                for (EventRecord eventInstance = logReader.ReadEvent(); eventInstance != null; eventInstance = logReader.ReadEvent())
                {
                    if (Globals.eventIds.Any() & !Globals.eventIds.Contains(eventInstance.Id))
                    {
                        continue;
                    }
                    eventCount++;
                    try
                    {
                        SysmonEvent sysmonEvent = new SysmonEvent
                        {
                            TimeCreated = eventInstance.TimeCreated,
                            EventId = eventInstance.Id,
                            RecordId = (int)eventInstance.RecordId,
                            RawXml = eventInstance.ToXml(),
                            Sent = false,
                            EntryAddedAt = DateTime.UtcNow,
                            Error = false
                        };
                        string pattern = @"<Data Name=['""]Image['""]>.*\\EDV\.exe</Data>";
                        Regex regex = new Regex(pattern);
                        Match match = regex.Match(sysmonEvent.RawXml);
                        if (match.Success) // if triggered by our own edr.exe process, skip
                        {
                            continue;
                        }
                        if (Globals._recordIds.Contains(sysmonEvent.RecordId))
                        {
                            continue;
                        }
                        eventArray.Add(sysmonEvent);
                        Globals._recentSysmonEvents.Add(sysmonEvent);
                        Globals._recordIds.Add(sysmonEvent.RecordId);
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Error processing event {eventInstance.RecordId} (EventId={eventInstance.Id}): {ex.Message}");
                    }
                }
                Utils.RemoveOldEvents();
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error accessing Sysmon log: {ex.Message}");
            Console.Error.WriteLine("Possible causes: Run as admin, verify Sysmon log, check query.");
        }
        return eventArray;
    }

    public static async Task ConnectWebSocket()
    {
        Console.WriteLine($"Connecting to {Globals.WebSocketUrl}...");
        await _webSocket.ConnectAsync(new Uri(Globals.WebSocketUrl), CancellationToken.None);
        Console.WriteLine("Connected!");
        Task receiveTask = ReceiveMessages();
        Task sendTask = GetEventsAndSendMessages();
        await Task.WhenAny(receiveTask, sendTask);
        await CloseWebSocket();
    }

    static async Task ReceiveMessages()
    {
        byte[] buffer = new byte[1024];
        StringBuilder readableResult = new StringBuilder();
        String copilotResult = "";
        while (_webSocket.State == WebSocketState.Open)
        {
            try
            {
                WebSocketReceiveResult result = await _webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
                if (result.MessageType == WebSocketMessageType.Text)
                {
                    string message = Encoding.UTF8.GetString(buffer, 0, result.Count);
                    readableResult.Append(message);
                    if (result.EndOfMessage)
                    {
                        string completeMessage = readableResult.ToString();
                        var jsonObjects = SplitJsonObjects(completeMessage);
                        foreach (var json in jsonObjects)
                        {
                            try
                            {
                                JsonDocument doc = JsonDocument.Parse(json);
                                string eventType = doc.RootElement.GetProperty("event").GetString();
                                switch (eventType)
                                {
                                    case "partCompleted":
                                    case "suggestedFollowups":
                                    case "received":
                                    case "startMessage":
                                    case "titleUpdate":
                                        if (!currentSysmonEvent.Sent)
                                        {
                                            Console.Write(" .");
                                        }
                                        break;
                                    case "appendText":
                                        var append = JsonSerializer.Deserialize<AppendTextEvent>(json).Text.Trim();
                                        if (copilotResult == "" && append != "" && append != "\n" && copilotResult != append)
                                        {
                                            copilotResult = append;
                                        }
                                        Console.Write(" .");
                                        break;
                                    case "done":
                                        Console.Write(" .");
                                        if (copilotResult != "")
                                        {
                                            Console.WriteLine($" {copilotResult}");
                                            if (copilotResult == "ALERT")
                                            {
                                                Task.Run(() => MessageBox.Show($"{currentSysmonEvent.RawXml}", $"ALERT - {currentSysmonEvent.RecordId} - {currentSysmonEvent.TimeCreated}", MessageBoxButtons.OK, MessageBoxIcon.Information));
                                            }
                                        }
                                        currentSysmonEvent.Sent = true;
                                        copilotResult = "";
                                        break;
                                    case "error": // too may requests
                                        Console.Error.WriteLine("Too many requests...");
                                        Globals._recordIds.Remove(currentSysmonEvent.RecordId);
                                        currentSysmonEvent.Error = true;
                                        copilotResult = "";
                                        Thread.Sleep(1000); // sleep longer
                                        break;
                                    default:
                                        Console.Error.WriteLine($"Unknown event type: {eventType}");
                                        currentSysmonEvent.Error = true;
                                        copilotResult = "";
                                        Thread.Sleep(1000); // sleep longer
                                        break;
                                }
                            }
                            catch (JsonException ex)
                            {
                                Console.Error.WriteLine($"JSON parsing error for object: {json}, Error: {ex.Message}");
                            }
                        }
                        readableResult.Clear();
                    }
                }
                else if (result.MessageType == WebSocketMessageType.Close)
                {
                    Console.Error.WriteLine("WebSocket closed by server.");
                    break;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Receive error: {ex.Message}");
                break;
            }
        }
    }

    // Helper method to split concatenated JSON objects
    static IEnumerable<string> SplitJsonObjects(string input)
    {
        var results = new List<string>();
        int braceCount = 0;
        int startIndex = 0;

        for (int i = 0; i < input.Length; i++)
        {
            if (input[i] == '{')
            {
                if (braceCount == 0)
                {
                    startIndex = i;
                }
                braceCount++;
            }
            else if (input[i] == '}')
            {
                braceCount--;
                if (braceCount == 0)
                {
                    results.Add(input.Substring(startIndex, i - startIndex + 1));
                }
            }
        }

        return results;
    }

    static async Task sendMessage(SysmonEvent evt)
    {
        currentSysmonEvent = evt;
        String escapedEvents = evt.RawXml
            .Replace("\\", "\\\\")   // Backslashes: \ -> \\
            .Replace("\"", "\\\"")   // Quotes: " -> \"
            .Replace("\n", "\\n")    // Newlines: \n -> \n
            .Replace("\r", "\\r")    // Carriage returns: \r -> \r
            .Replace("\t", "\\t");   // Tabs: \t -> \t

        String message = $"{{\"event\":\"send\",\"conversationId\":\"{Globals.conversationId}\",\"content\":[{{\"type\":\"text\",\"text\":\"This is a Sysmon event of my Windows host. Does the event indicate anything malicious happening on my host? You can use the previous events I already sent if it helps contextualizing this new event. If yes, please respond with just \\\"ALERT\\\". If not, or you are not certain, respond with just \\\"OK\\\" (also in the case you do not really understand the event). Disregard domain names (do not want false positives). Sysmon event raw XML is: {escapedEvents}\"}}],\"mode\":\"chat\",\"context\":{{}}}}";
        try
        {
            byte[] messageBuffer = Encoding.UTF8.GetBytes(message);
            Console.Write($"RecordId={evt.RecordId}, EventId={evt.EventId}, TimeCreated={evt.TimeCreated} . . .");
            await _webSocket.SendAsync(new ArraySegment<byte>(messageBuffer), WebSocketMessageType.Text, true, CancellationToken.None);
            while (!currentSysmonEvent.Sent)
            {
                if (currentSysmonEvent.Error)
                {
                    currentSysmonEvent.Error = false;
                    sendMessage(evt);
                }
                Thread.Sleep(5);
            }
            Utils.RemoveOldEvents();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Send error: {ex.Message}");
        }
    }

    static async Task GetEventsAndSendMessages()
    {
        while (_webSocket.State == WebSocketState.Open)
        {

            List<SysmonEvent> events = GetEvents();
            foreach (var evt in events)
            {
                await sendMessage(evt);
            }
            Thread.Sleep(20);
        }
    }

    static async Task CloseWebSocket()
    {
        try
        {
            if (_webSocket.State == WebSocketState.Open)
            {
                await _webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", CancellationToken.None);
                Console.WriteLine("WebSocket closed gracefully.");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Close error: {ex.Message}");
        }
        finally
        {
            _webSocket.Dispose();
            _webSocket = new ClientWebSocket(); // Create a new instance for reconnection
        }
    }
}

public class SysmonEventProcessor
{
    private readonly SysmonEvent _event;
    private readonly string _conversationId;
    private readonly string _webSocketUrl;
    private readonly Guid _processorId = Guid.NewGuid();

    public SysmonEventProcessor(SysmonEvent evt, string conversationId, string webSocketUrl)
    {
        _event = evt ?? throw new ArgumentNullException(nameof(evt));
        _conversationId = conversationId ?? throw new ArgumentNullException(nameof(conversationId));
        _webSocketUrl = webSocketUrl ?? throw new ArgumentNullException(nameof(webSocketUrl));
    }

    static void RemoveEventFromListForErrorCase(SysmonEvent evt)
    {
        lock (Globals._recordIdsLock)
        {
            Globals._recordIds.Remove(evt.RecordId);
            Globals._recentSysmonEvents.Remove(evt);
        }
    }

    public async Task ProcessAsync()
    {
        ClientWebSocket webSocket = null;
        CancellationTokenSource timeoutCts = null;

        try
        {
            webSocket = new ClientWebSocket();
            await webSocket.ConnectAsync(new Uri(_webSocketUrl), CancellationToken.None);
            string escapedEvents = _event.RawXml
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\n", "\\n")
                .Replace("\r", "\\r")
                .Replace("\t", "\\t");

            string message = $"{{\"event\":\"send\",\"conversationId\":\"{_conversationId}\",\"content\":[{{\"type\":\"text\",\"text\":\"This is a Sysmon event of my Windows host. Does the event indicate anything malicious happening on my host? You can use the previous events I already sent if it helps contextualizing this new event. If yes, please respond with just \\\"ALERT\\\". If not, or you are not certain, respond with just \\\"OK\\\" (also in the case you do not really understand the event). Disregard domain names (do not want false positives). Sysmon event raw XML is: {escapedEvents}\"}}],\"mode\":\"chat\",\"context\":{{}}}}";
            byte[] messageBuffer = Encoding.UTF8.GetBytes(message);
            await webSocket.SendAsync(new ArraySegment<byte>(messageBuffer), WebSocketMessageType.Text, true, CancellationToken.None);

            timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            string copilotResult = "";
            byte[] buffer = new byte[1024];
            StringBuilder readableResult = new StringBuilder();
            string output = "";

            while (webSocket.State == WebSocketState.Open)
            {
                var result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), timeoutCts.Token);
                if (result.MessageType == WebSocketMessageType.Text)
                {
                    string messagePart = Encoding.UTF8.GetString(buffer, 0, result.Count);
                    readableResult.Append(messagePart);

                    if (result.EndOfMessage)
                    {
                        string completeMessage = readableResult.ToString();
                        var jsonObjects = SplitJsonObjects(completeMessage);
                        foreach (var json in jsonObjects)
                        {
                            try
                            {
                                JsonDocument doc = JsonDocument.Parse(json);
                                string eventType = doc.RootElement.GetProperty("event").GetString();
                                switch (eventType)
                                {
                                    case "partCompleted":
                                    case "suggestedFollowups":
                                    case "received":
                                    case "startMessage":
                                    case "titleUpdate":
                                        if (!_event.Sent)
                                        {
                                            output += " .";
                                        }
                                        break;
                                    case "appendText":
                                        var append = JsonSerializer.Deserialize<AppendTextEvent>(json).Text.Trim();
                                        if (copilotResult == "" && append != "" && append != "\n" && copilotResult != append)
                                        {
                                            copilotResult = append;
                                        }
                                        output += " .";
                                        break;
                                    case "done":
                                        output += " .";
                                        if (copilotResult != "")
                                        {
                                            Console.WriteLine($"RecordId={_event.RecordId}, EventId={_event.EventId}, TimeCreated={_event.TimeCreated} {output} {copilotResult}");
                                            if (copilotResult == "ALERT")
                                            {
                                                Task.Run(() => MessageBox.Show($"{_event.RawXml}", $"ALERT - {_event.RecordId} - {_event.TimeCreated}", MessageBoxButtons.OK, MessageBoxIcon.Information));
                                            }
                                        }
                                        _event.Sent = true;
                                        if (webSocket.State == WebSocketState.Open)
                                        {
                                            await webSocket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "Done received", CancellationToken.None);
                                        }
                                        timeoutCts.Cancel();
                                        return;
                                    case "error":
                                        RemoveEventFromListForErrorCase(_event);
                                        Console.Error.WriteLine("Too many requests...");
                                        return;
                                    default:
                                        RemoveEventFromListForErrorCase(_event);
                                        Console.Error.WriteLine($"Unknown event type: {eventType}");
                                        return;
                                }
                            }
                            catch (JsonException ex)
                            {
                                Console.Error.WriteLine($"[{_processorId}] JSON parsing error for object: {json}, Error: {ex.Message}");
                                RemoveEventFromListForErrorCase(_event);
                                return;
                            }
                        }
                        readableResult.Clear();
                    }
                }
                else if (result.MessageType == WebSocketMessageType.Close)
                {
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
            RemoveEventFromListForErrorCase(_event);
            Console.Error.WriteLine($"[{_processorId}] Timeout: No complete response received within 30 seconds for RecordId={_event.RecordId}");
        }
        catch (Exception ex)
        {
            RemoveEventFromListForErrorCase(_event);
            Console.Error.WriteLine($"[{_processorId}] Error for RecordId={_event.RecordId}: {ex.Message}");
        }
        finally
        {
            timeoutCts?.Dispose();
            if (webSocket != null)
            {
                try
                {
                    if (webSocket.State == WebSocketState.Open)
                    {
                        await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", CancellationToken.None);
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[{_processorId}] Error closing WebSocket for RecordId={_event.RecordId}: {ex.Message}");
                }
                webSocket.Dispose();
            }
        }
    }

    private static IEnumerable<string> SplitJsonObjects(string input)
    {
        var results = new List<string>();
        int braceCount = 0;
        int startIndex = 0;

        for (int i = 0; i < input.Length; i++)
        {
            if (input[i] == '{')
            {
                if (braceCount == 0)
                {
                    startIndex = i;
                }
                braceCount++;
            }
            else if (input[i] == '}')
            {
                braceCount--;
                if (braceCount == 0)
                {
                    results.Add(input.Substring(startIndex, i - startIndex + 1));
                }
            }
        }

        return results;
    }
}

class ConcurrentExecutor
{
    private static readonly int queryOnlyForLastEventsInMinutes = -3;
    private static DateTime initialTime;
    private static readonly ConcurrentQueue<SysmonEvent> _eventQueue = new ConcurrentQueue<SysmonEvent>();
    private static readonly SemaphoreSlim _connectionLimiter = new SemaphoreSlim(Globals.TOTAL_CONCURRENT_REQUESTS, Globals.TOTAL_CONCURRENT_REQUESTS);

    static List<SysmonEvent> GetEvents()
    {
        List<SysmonEvent> eventArray = new List<SysmonEvent>();
        DateTime endTime = DateTime.UtcNow;
        DateTime startTime = endTime;
        if (Globals.firstRun)
        {
            initialTime = startTime;
            Globals.firstRun = false;
        }
        else
        {
            startTime = endTime.AddMinutes(Globals.queryOnlyForLastEventsInMinutes);
            if (startTime < initialTime)
            {
                startTime = initialTime;
            }
        }
        string query = $"*[System[TimeCreated[@SystemTime>='{startTime.ToUniversalTime():s}Z' and @SystemTime<='{endTime.ToUniversalTime():s}Z']]]";

        try
        {
            EventLogQuery eventQuery = new EventLogQuery("Microsoft-Windows-Sysmon/Operational", PathType.LogName, query);
            using (EventLogReader logReader = new EventLogReader(eventQuery))
            {
                int eventCount = 0;
                for (EventRecord eventInstance = logReader.ReadEvent(); eventInstance != null; eventInstance = logReader.ReadEvent())
                {
                    if (Globals.eventIds.Any() && !Globals.eventIds.Contains(eventInstance.Id))
                    {
                        continue;
                    }
                    eventCount++;
                    try
                    {
                        SysmonEvent sysmonEvent = new SysmonEvent
                        {
                            TimeCreated = eventInstance.TimeCreated,
                            EventId = eventInstance.Id,
                            RecordId = (int)eventInstance.RecordId,
                            RawXml = eventInstance.ToXml(),
                            Sent = false,
                            EntryAddedAt = DateTime.UtcNow
                        };
                        string pattern = @"<Data Name=['""]Image['""]>.*\\EDV\.exe</Data>";
                        Regex regex = new Regex(pattern);
                        Match match = regex.Match(sysmonEvent.RawXml);
                        if (match.Success) // if triggered by our own edr.exe process, skip
                        {
                            continue;
                        }
                        if (Globals._recordIds.Contains(sysmonEvent.RecordId))
                        {
                            continue;
                        }
                        eventArray.Add(sysmonEvent);
                        lock (Globals._recordIdsLock)
                        {
                            Globals._recentSysmonEvents.Add(sysmonEvent);
                            Globals._recordIds.Add(sysmonEvent.RecordId);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Error processing event {eventInstance.RecordId} (EventId={eventInstance.Id}): {ex.Message}");
                    }
                }
                Utils.RemoveOldEvents();
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error accessing Sysmon log: {ex.Message}");
            Console.Error.WriteLine("Possible causes: Run as admin, verify Sysmon log, check query.");
        }
        return eventArray;
    }

    public static async Task GetEventsAndSendMessages()
    {
        var workers = Enumerable.Range(0, Globals.TOTAL_CONCURRENT_REQUESTS)
            .Select(_ => Task.Run(() => ProcessEventQueueAsync()))
            .ToArray();
        while (true)
        {
            List<SysmonEvent> newEvents = GetEvents();
            if (newEvents.Any())
            {
                var sortedEvents = newEvents.OrderBy(e => e.RecordId).ToList();
                foreach (var evt in sortedEvents)
                {
                    if (!_eventQueue.Any(e => e.RecordId == evt.RecordId))
                    {
                        _eventQueue.Enqueue(evt);
                    }
                }
            }
            await Task.Delay(500);
        }
    }

    static async Task ProcessEventQueueAsync()
    {
        while (true)
        {
            if (_eventQueue.TryDequeue(out SysmonEvent evt))
            {
                try
                {
                    await _connectionLimiter.WaitAsync();
                    var processor = new SysmonEventProcessor(evt, Globals.conversationId, Globals.WebSocketUrl);
                    await processor.ProcessAsync();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error processing RecordId={evt.RecordId}: {ex.Message}");
                }
                finally
                {
                    _connectionLimiter.Release();
                }
            }
            else
            {
                await Task.Delay(200);
            }
        }
    }
}

class Program
{
    static async Task GetNewConversationId()
    {
        try
        {
            HttpClient client = new HttpClient();
            client.BaseAddress = new Uri($"https://{Globals._baseDomain}");
            client.DefaultRequestHeaders.Add("Host", Globals._baseDomain);
            var payload = new { startNewConversation = true };
            string jsonPayload = JsonSerializer.Serialize(payload);
            var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");
            HttpResponseMessage response = await client.PostAsync("/c/api/start?dpwa=1", content);
            response.EnsureSuccessStatusCode();
            string responseBody = await response.Content.ReadAsStringAsync();
            JsonDocument doc = JsonDocument.Parse(responseBody);
            JsonElement root = doc.RootElement;
            if (root.TryGetProperty("currentConversationId", out JsonElement conversationIdElement))
            {
                string cId = conversationIdElement.GetString();
                Globals.conversationId = cId;
                Console.WriteLine($"\n\n***** Use the following as the <conversationId> parameter: {cId} ******\n");
            }
            else
            {
                Console.Error.WriteLine("currentConversationId not found in the response.");
                Environment.Exit(1);
            }
        }
        catch (HttpRequestException e)
        {
            Console.Error.WriteLine($"Request error: {e.Message}");
        }
        catch (JsonException e)
        {
            Console.Error.WriteLine($"JSON parsing error: {e.Message}");
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"Unexpected error: {e.Message}");
        }
    }

    static void Help()
    {
        Console.WriteLine("Typical Usage: EDV.exe MODE [conversationId] [eventIds]");
        Console.WriteLine("Example: EDV.exe sync myConversationId 1,3,22");
        Console.WriteLine("         EDV.exe async myConversationId\n\n");
    }

    static async Task Main(string[] args)
    {
        string mode = "";
        Globals.eventIds = new List<int>();
        if (args.Length < 1)
        {
            Console.WriteLine("MODE parameter is required");
            Help();
            Environment.Exit(0);
        }
        mode = args[0].Trim();
        if (mode != "sync" && mode != "async")
        {
            Console.WriteLine("Invalid MODE parameter value provided");
            Help();
            Environment.Exit(0);
        }
        if (args.Length < 2)
        {
            await GetNewConversationId();
            Help();
            Console.WriteLine("Do you want to continue for all event types? (y|n)");
            string response = Console.ReadLine()?.Trim().ToLower();
            if (response != "y")
            {
                Console.WriteLine("Exiting...");
                Environment.Exit(0);
            }
        }
        else
        {
            Globals.conversationId = args[1].Trim();
            if (string.IsNullOrWhiteSpace(Globals.conversationId) || Globals.conversationId.Length != 21)
            {
                Console.Error.WriteLine("Error: conversationId needs to be 21 characters.");
                Environment.Exit(1);
            }
            Console.WriteLine($"conversationId: {Globals.conversationId}");
            if (args.Length > 1 && !string.IsNullOrWhiteSpace(args[1]))
            {
                try
                {
                    string eventIdsInput = args[2].Trim();
                    Globals.eventIds = eventIdsInput.Split(',')
                                           .Select(item => item.Trim())
                                           .Where(item => !string.IsNullOrEmpty(item))
                                           .Select(int.Parse)
                                           .ToList();
                }
                catch (FormatException)
                {
                    Console.Error.WriteLine("Error: eventIds must be a comma-separated list of integers (e.g., 1,3,22).");
                    Environment.Exit(1);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error parsing eventIds: {ex.Message}");
                    Environment.Exit(1);
                }
            }
        }

        if (mode == "sync")
        {
            await SyncExecutor.ConnectWebSocket();
        }
        else
        {
            await ConcurrentExecutor.GetEventsAndSendMessages();
        }
    }
}
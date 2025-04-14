# EDV
Endpoint Protection & Vibes is a POC that grabs Sysmon events, sends them to Copilot Chat for analysis, and raises alert (message boxes) in case Copilot believes the event is malicious.

This tool is not intended for production use... or anything else really :)

## Background
For more details on how EDV works, checkout this blog post:  
- [EDV - Endpoint Detection & Vibes](https://tierzerosecurity.co.nz/2025/04/14/edv.html)

## Usage
The tool reads events from Sysmon, which must be installed and enabled for the tool to function properly.

EDV can be compiled using Visual Studio. It was only tested with .NET Framework 4.8.1 and on a Windows 11 system.

The tool needs to be executed by a process running at a high integrity level, or Sysmon events cannot be queried.

```
Typical Usage: EDV.exe MODE [conversationId] [eventIds]
Example: EDV.exe sync myConversationId 1,3,22
         EDV.exe async myConversationId
```

The tool supports 2 different running modes:
- `sync`
- `async`

The `sync` mode establishes a single websocket connection with the Copilot Chat endpoint, and sends all event synchronously reusing the same connection.

The `async` mode, establishes new connection for each event and sends events in parallel. This cannot be achieved on a single connection, due to rate limiting.

The tool also accepts these optional parameters:
- Conversation ID
- Event IDs

The tool allows to specify which `conversationId` to use for communication. If you run the tool without the `conversationId` argument, it will use the Copilot API to get a new ID.

The tool also allows to specify which events to consider. Sysmon events range from 1 to 31.

### start.bat
Depending on the activity on the host, several events of the same type could be triggered.

For this reason, a Batch file is also provided which allows to create multiple EDV.exe processes. Each process will monitor only two Sysmon events at the time.

To use this Batch, you need to specify the mode you want to run it with (`sync` / `async`) and a valid `conversationId`.

## License
This tool is released under the [MIT License](https://opensource.org/licenses/MIT).

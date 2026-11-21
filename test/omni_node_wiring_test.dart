import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:omni_core_ui/omni_core_ui.dart';

// The wiring against a fake hub: probe honesty (delegate only when a node
// really answers) and the SoT §15 wire shape for delegate appends —
// action + payload only: no previous_hash, no sequence, no app_context.

class _FakeHub {
  HttpServer? server;
  Map<String, dynamic>? lastAppendBody;

  Future<int> start() async {
    server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server!.listen((req) async {
      req.response.headers.contentType = ContentType.json;
      if (req.uri.path == '/api/v1/telemetry/node-health') {
        req.response.write(jsonEncode({
          'status': 'ONLINE',
          'version': '8.33.2',
          'node_id': 'cd' * 32,
          'active_peers': 3,
        }));
      } else if (req.uri.path == '/api/events/append') {
        final raw = await utf8.decoder.bind(req).join();
        lastAppendBody = jsonDecode(raw) as Map<String, dynamic>;
        req.response
            .write(jsonEncode({'status': 'SUCCESS', 'event_id': '0xfeed'}));
      } else {
        req.response.statusCode = 404;
        req.response.write('{}');
      }
      await req.response.close();
    });
    return server!.port;
  }

  Future<void> stop() async => server?.close(force: true);
}

OmniNodeWiring _wiringFor(int port) => OmniNodeWiring(
      appContext: 'kickback',
      store: LocalEventStore(),
      hub: OmniHubClient(host: '127.0.0.1', ipcPort: port, telemetryPort: port),
    );

void main() {
  test('probe: a node that answers means delegate, with its real status',
      () async {
    final hub = _FakeHub();
    final port = await hub.start();
    addTearDown(hub.stop);
    final wiring = _wiringFor(port);

    final result = await wiring.initializeNode();

    expect(wiring.isInitialized, isTrue);
    expect(result.mode, OmniNodeMode.delegate);
    expect(result.uiStatus, OmniUiStatus.connected);
    expect(result.daemonVersion, '8.33.2');
    expect(result.peerCount, 3);
    expect(wiring.mode, OmniNodeMode.delegate);
    expect(wiring.uiStatus.value, OmniUiStatus.connected);
  });

  test('probe: silence means standalone, said plainly', () async {
    // Bind then close a server to get a port nothing answers on.
    final probe = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final deadPort = probe.port;
    await probe.close(force: true);
    final wiring = _wiringFor(deadPort);

    final result = await wiring.probe();

    expect(result.mode, OmniNodeMode.standalone);
    expect(result.uiStatus, OmniUiStatus.unreachable);
    expect(wiring.mode, OmniNodeMode.standalone);
  });

  test('delegate append sends action + payload ONLY (§15 shape)', () async {
    final hub = _FakeHub();
    final port = await hub.start();
    addTearDown(hub.stop);
    final wiring = _wiringFor(port);

    final res = await wiring.appendToNode('KICKBACK_POST', {'text': 'hi'});

    expect(res, isNotNull);
    expect(res!['event_id'], '0xfeed');
    final body = hub.lastAppendBody!;
    expect(body.keys.toSet(), {'action', 'payload'});
    expect(body['action'], 'KICKBACK_POST');
    expect(body.containsKey('previous_hash'), isFalse);
    expect(body.containsKey('sequence'), isFalse);
    expect(body.containsKey('app_context'), isFalse);
  });
}

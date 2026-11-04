// Pure-Dart tests for the OTA downloader: local HttpServer fakes GitHub's redirect, a stalled link,
// a resumed download, a bad checksum and a missing asset.
import 'dart:async';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:omni_core_ui/omni_core_ui.dart';

List<int> _payload(int n) => List<int>.generate(n, (i) => (i * 31 + 7) & 0xff);

Future<HttpServer> _server(
  Future<void> Function(HttpRequest req, int hit) handler,
) async {
  final s = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  var hits = 0;
  s.listen((req) async {
    hits++;
    try {
      await handler(req, hits);
    } catch (_) {}
  });
  return s;
}

int? _rangeStart(HttpRequest req) {
  final r = req.headers.value(HttpHeaders.rangeHeader);
  if (r == null) return null;
  return int.parse(RegExp(r'bytes=(\d+)-').firstMatch(r)!.group(1)!);
}

OtaDownloader _fast() => OtaDownloader(
  connectTimeout: const Duration(seconds: 2),
  idleTimeout: const Duration(milliseconds: 400),
  maxAttempts: 4,
  backoff: (_) => const Duration(milliseconds: 10),
);

void main() {
  late Directory tmp;
  setUp(() async => tmp = await Directory.systemTemp.createTemp('ota_dl_test'));
  tearDown(() async => tmp.delete(recursive: true));

  final data = _payload(300000);
  final sum = sha256.convert(data).toString();

  test('follows a redirect and verifies SHA-256', () async {
    final s = await _server((req, _) async {
      if (req.uri.path == '/release') {
        req.response
          ..statusCode = 302
          ..headers.set(HttpHeaders.locationHeader, '/cdn/app.apk');
      } else {
        req.response.contentLength = data.length;
        req.response.add(data);
      }
      await req.response.close();
    });
    final f = await _fast().download(
      Uri.parse('http://127.0.0.1:${s.port}/release'),
      File('${tmp.path}/a.apk'),
      sha256: sum,
    );
    expect(await f.readAsBytes(), data);
    await s.close(force: true);
  });

  test('a stalled link is retried and resumes with Range', () async {
    final ranges = <int?>[];
    final s = await _server((req, hit) async {
      final start = _rangeStart(req);
      ranges.add(start);
      if (hit == 1) {
        // send half, then go silent (longer than the idle timeout)
        req.response.contentLength = data.length;
        req.response.add(data.sublist(0, 150000));
        await req.response.flush();
        await Future<void>.delayed(const Duration(seconds: 2));
        await req.response.close();
        return;
      }
      final from = start ?? 0;
      req.response
        ..statusCode = from > 0 ? 206 : 200
        ..contentLength = data.length - from;
      req.response.add(data.sublist(from));
      await req.response.close();
    });
    var maxAttempt = 0;
    final f = await _fast().download(
      Uri.parse('http://127.0.0.1:${s.port}/x.apk'),
      File('${tmp.path}/b.apk'),
      sha256: sum,
      onProgress: (_, __, a) => maxAttempt = a,
    );
    expect(await f.readAsBytes(), data);
    expect(ranges.first, isNull);
    expect(ranges[1], greaterThan(0)); // resumed, not restarted
    expect(maxAttempt, 2);
    await s.close(force: true);
  });

  test('a server that ignores Range restarts cleanly', () async {
    final s = await _server((req, hit) async {
      req.response.contentLength = data.length;
      if (hit == 1) {
        req.response.add(data.sublist(0, 1000));
        await req.response.flush();
        await Future<void>.delayed(const Duration(seconds: 2));
      } else {
        req.response.add(data); // 200, full body
      }
      await req.response.close();
    });
    final f = await _fast().download(
      Uri.parse('http://127.0.0.1:${s.port}/x.apk'),
      File('${tmp.path}/c.apk'),
      sha256: sum,
    );
    expect(await f.readAsBytes(), data);
    await s.close(force: true);
  });

  test('checksum mismatch is never returned and the file is removed', () async {
    final s = await _server((req, _) async {
      req.response.add(_payload(5000));
      await req.response.close();
    });
    final dest = File('${tmp.path}/d.apk');
    await expectLater(
      _fast().download(
        Uri.parse('http://127.0.0.1:${s.port}/x.apk'),
        dest,
        sha256: sum,
      ),
      throwsA(isA<OtaDownloadException>()),
    );
    expect(await dest.exists(), isFalse);
    await s.close(force: true);
  });

  test('404 fails at once without retrying', () async {
    var hits = 0;
    final s = await _server((req, _) async {
      hits++;
      req.response.statusCode = 404;
      await req.response.close();
    });
    await expectLater(
      _fast().download(
        Uri.parse('http://127.0.0.1:${s.port}/x.apk'),
        File('${tmp.path}/e.apk'),
      ),
      throwsA(
        isA<OtaDownloadException>().having(
          (e) => e.retryable,
          'retryable',
          false,
        ),
      ),
    );
    expect(hits, 1);
    await s.close(force: true);
  });

  test('gives up after maxAttempts on a dead link', () async {
    final s = await _server((req, _) async {
      await Future<void>.delayed(
        const Duration(seconds: 2),
      ); // never answers in time
      await req.response.close();
    });
    final sw = Stopwatch()..start();
    await expectLater(
      _fast().download(
        Uri.parse('http://127.0.0.1:${s.port}/x.apk'),
        File('${tmp.path}/f.apk'),
      ),
      throwsA(
        isA<OtaDownloadException>().having(
          (e) => '$e',
          'msg',
          contains('gave up after 4'),
        ),
      ),
    );
    expect(sw.elapsed, lessThan(const Duration(seconds: 6)));
    await s.close(force: true);
  });

  test(
    'loopback server hands the verified file over and refuses other paths',
    () async {
      final f = File('${tmp.path}/g.apk')..writeAsBytesSync(data);
      final srv = await LoopbackFileServer.serve(f, 'g.apk');
      expect(srv.url.host, '127.0.0.1');
      final c = HttpClient();
      final ok = await (await c.getUrl(srv.url)).close();
      final body = await ok.fold<List<int>>(<int>[], (a, b) => a..addAll(b));
      expect(ok.statusCode, 200);
      expect(body, data);
      final bad = await (await c.getUrl(srv.url.replace(path: '/guess/g.apk')))
          .close();
      expect(bad.statusCode, 404);
      await bad.drain<void>();
      c.close(force: true);
      await srv.close();
    },
  );
}

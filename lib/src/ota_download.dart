import 'dart:async';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';

/// ============================================================================
/// OTA DOWNLOADER (omni_core_ui), pure Dart
/// ============================================================================
/// Downloads an update APK before anything is handed to Android's installer, so
/// a slow or stalling link no longer kills the update:
///
/// * Redirects (GitHub Releases -> its asset CDN) are followed by hand, fresh on
///   every attempt, so a short-lived signed CDN link never goes stale.
/// * A generous connect timeout and an *idle* timeout (time with no new bytes),
///   instead of the fixed 10 s socket timeout that ota_update's OkHttp client
///   uses and that apps can't change.
/// * Several attempts with backoff. A retry resumes where the last one stopped
///   (HTTP Range); a server that ignores Range just starts over.
/// * The SHA-256 from the update manifest is checked here. A mismatch deletes
///   the file and counts as a failed attempt; it is never installed.
/// * 4xx answers (missing asset, bad link) fail at once: retrying can't help.
///
/// The source URL is any http(s) URL, so OmniNet peers that serve the same bytes
/// can use this downloader too; the SHA-256 is what makes a peer safe.
/// ============================================================================

typedef OtaProgress = void Function(int received, int? total, int attempt);

class OtaDownloadException implements Exception {
  final String message;

  /// True when retrying might help (timeouts, dropped links, 5xx).
  final bool retryable;
  OtaDownloadException(this.message, {this.retryable = true});
  @override
  String toString() => message;
}

class OtaDownloader {
  final Duration connectTimeout;

  /// Longest wait for the next bytes before the attempt is called stalled.
  final Duration idleTimeout;
  final int maxAttempts;
  final Duration Function(int failedAttempts) backoff;
  final int maxRedirects;

  OtaDownloader({
    this.connectTimeout = const Duration(seconds: 30),
    this.idleTimeout = const Duration(seconds: 45),
    this.maxAttempts = 5,
    Duration Function(int failedAttempts)? backoff,
    this.maxRedirects = 6,
  }) : backoff = backoff ?? ((n) => Duration(seconds: min(2 * n, 10)));

  bool _cancelled = false;
  HttpClient? _client;

  /// Stops the download in progress; [download] then throws.
  void cancel() {
    _cancelled = true;
    _client?.close(force: true);
  }

  /// Downloads [url] into [dest] and returns it once its SHA-256 matches
  /// [sha256] (skipped when null or empty). Throws [OtaDownloadException].
  Future<File> download(
    Uri url,
    File dest, {
    String? sha256,
    OtaProgress? onProgress,
  }) async {
    final want = (sha256 ?? '').trim().toLowerCase();
    if (await dest.exists()) await dest.delete();
    Object? lastError;
    for (var attempt = 1; attempt <= maxAttempts; attempt++) {
      if (_cancelled) throw OtaDownloadException('cancelled', retryable: false);
      try {
        await _attempt(url, dest, attempt, onProgress);
        if (want.isNotEmpty) {
          final got = (await _sha256Of(dest)).toLowerCase();
          if (got != want) {
            await dest.delete();
            throw OtaDownloadException('checksum mismatch');
          }
        }
        return dest;
      } on OtaDownloadException catch (e) {
        lastError = e;
        if (!e.retryable || _cancelled) rethrow;
      } on TimeoutException {
        lastError = OtaDownloadException('timeout');
      } on IOException catch (e) {
        lastError = OtaDownloadException('connection lost (${e.runtimeType})');
      }
      if (_cancelled) throw OtaDownloadException('cancelled', retryable: false);
      if (attempt < maxAttempts) await Future<void>.delayed(backoff(attempt));
    }
    throw OtaDownloadException(
      'gave up after $maxAttempts tries: $lastError',
      retryable: false,
    );
  }

  Future<void> _attempt(
    Uri url,
    File dest,
    int attempt,
    OtaProgress? onProgress,
  ) async {
    final client = HttpClient()
      ..connectionTimeout = connectTimeout
      ..idleTimeout = const Duration(seconds: 5)
      ..userAgent = 'omni-ota/1';
    _client = client;
    try {
      final have = await dest.exists() ? await dest.length() : 0;
      var target = url;
      HttpClientResponse? res;
      for (var hop = 0; hop <= maxRedirects; hop++) {
        final req = await client.getUrl(target).timeout(connectTimeout);
        req.followRedirects = false;
        if (have > 0) req.headers.set(HttpHeaders.rangeHeader, 'bytes=$have-');
        final r = await req.close().timeout(idleTimeout);
        if (r.isRedirect) {
          final loc = r.headers.value(HttpHeaders.locationHeader);
          await r.drain<void>().catchError((_) {});
          if (loc == null)
            throw OtaDownloadException('redirect without a location');
          target = target.resolve(loc);
          continue;
        }
        res = r;
        break;
      }
      if (res == null)
        throw OtaDownloadException('too many redirects', retryable: false);

      final code = res.statusCode;
      if (code == 416 && have > 0) {
        // Asked past the end: what we have may already be the whole file.
        await res.drain<void>().catchError((_) {});
        return;
      }
      if (code >= 400 && code < 500 && code != 408 && code != 429) {
        await res.drain<void>().catchError((_) {});
        throw OtaDownloadException('server said HTTP $code', retryable: false);
      }
      if (code != 200 && code != 206) {
        await res.drain<void>().catchError((_) {});
        throw OtaDownloadException('server said HTTP $code');
      }

      final resuming = code == 206 && have > 0;
      var received = resuming ? have : 0;
      final len = res.contentLength;
      final total = len < 0 ? null : (resuming ? have + len : len);
      final sink = dest.openWrite(
        mode: resuming ? FileMode.append : FileMode.write,
      );
      try {
        await for (final chunk in res.timeout(idleTimeout)) {
          if (_cancelled)
            throw OtaDownloadException('cancelled', retryable: false);
          sink.add(chunk);
          received += chunk.length;
          onProgress?.call(received, total, attempt);
        }
      } finally {
        await sink.flush();
        await sink.close();
      }
      if (total != null && received < total) {
        throw OtaDownloadException(
          'download cut short ($received of $total bytes)',
        );
      }
    } finally {
      client.close(force: true);
      if (identical(_client, client)) _client = null;
    }
  }

  static Future<String> _sha256Of(File f) async =>
      (await sha256.bind(f.openRead()).first).toString();
}

/// Serves one verified file on 127.0.0.1 (random port, unguessable path) so the
/// Android installer plugin, which only takes a URL, picks it up instantly from
/// this phone instead of the internet. Closes itself after [ttl].
class LoopbackFileServer {
  final HttpServer _server;
  final String path;
  Timer? _timer;

  LoopbackFileServer._(this._server, this.path);

  Uri get url => Uri.parse('http://127.0.0.1:${_server.port}$path');

  static Future<LoopbackFileServer> serve(
    File file,
    String name, {
    Duration ttl = const Duration(minutes: 5),
  }) async {
    final rnd = Random.secure();
    final token = List.generate(
      16,
      (_) => rnd.nextInt(256).toRadixString(16).padLeft(2, '0'),
    ).join();
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final s = LoopbackFileServer._(server, '/$token/$name');
    s._timer = Timer(ttl, s.close);
    server.listen((req) async {
      final res = req.response;
      try {
        if (req.uri.path != s.path || req.method != 'GET') {
          res.statusCode = HttpStatus.notFound;
        } else {
          res.headers.contentType = ContentType(
            'application',
            'vnd.android.package-archive',
          );
          res.contentLength = await file.length();
          await res.addStream(file.openRead());
        }
      } catch (_) {
        // the reader went away; nothing to do
      } finally {
        await res.close().catchError((_) {});
      }
    });
    return s;
  }

  Future<void> close() async {
    _timer?.cancel();
    await _server.close(force: true);
  }
}

// Pure-Dart tests (mirrored in the sandbox harness with package:test) for OtaSourceResolver (omni_core_ui 0.1.3): a fake Omni Node (daemon v8.30.0
// /api/updates/manifest + /api/updates/file/<sha256>, local token) and a fake GitHub Releases
// (manifest + redirect to a CDN path), both on loopback.
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:omni_core_ui/omni_core_ui.dart';

List<int> _payload(int n, int salt) => List<int>.generate(n, (i) => (i * 31 + salt) & 0xff);
String _hex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

class _Keys {
  final SimpleKeyPair pair;
  final String pubHex;
  _Keys(this.pair, this.pubHex);
  static Future<_Keys> make() async {
    final p = await Ed25519().newKeyPair();
    final pub = await p.extractPublicKey();
    return _Keys(p, _hex(pub.bytes));
  }

  Future<Map<String, dynamic>> sign(Map<String, dynamic> m) async {
    final unsigned = Map<String, dynamic>.from(m)..remove('signature');
    final sig = await Ed25519().sign(utf8.encode(canonicalJson(unsigned)), keyPair: pair);
    return {...unsigned, 'signature': _hex(sig.bytes)};
  }
}

Map<String, dynamic> _manifest(int build, String url, String sha) => {
      'tag': '0.1.$build',
      'build': build,
      'transport': 'github',
      'apps': {
        'plaza-brawler': {'url': url, 'sha256': sha},
      },
    };

/// Fake Omni Node on loopback.
class FakeNode {
  late HttpServer server;
  String? requiredToken;
  Map<String, dynamic>? manifest; // null -> 404
  Map<String, List<int>> files = {};
  int manifestHits = 0;
  int fileHits = 0;
  final List<String?> tokensSeen = [];
  int? fileStatus; // force an HTTP status on file requests

  Future<void> start() async {
    server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((req) async {
      final res = req.response;
      try {
        final tok = req.headers.value('X-Omni-Local-Token');
        tokensSeen.add(tok);
        if (requiredToken != null && tok != requiredToken) {
          res.statusCode = 401;
          res.write('{"status":"ERROR","message":"missing or invalid local token"}');
        } else if (req.uri.path == '/api/updates/manifest') {
          manifestHits++;
          if (manifest == null) {
            res.statusCode = 404;
            res.write('{"status":"ERROR","message":"no verified update manifest yet"}');
          } else {
            res.headers.set('X-Omni-Update-Source', 'github');
            res.write(const JsonEncoder.withIndent('  ').convert(manifest));
          }
        } else if (req.uri.path.startsWith('/api/updates/file/')) {
          fileHits++;
          final sha = req.uri.path.split('/').last;
          final body = files[sha];
          if (fileStatus != null) {
            res.statusCode = fileStatus!;
          } else if (body == null) {
            res.statusCode = 404;
          } else {
            res.headers.set('X-Omni-Update-Source', 'cache');
            res.contentLength = body.length;
            res.add(body);
          }
        } else {
          res.statusCode = 404;
        }
      } catch (_) {}
      await res.close().catchError((_) {});
    });
  }

  String get base => 'http://127.0.0.1:${server.port}';
  Future<void> stop() => server.close(force: true);
}

/// Fake GitHub Releases: /latest/update-manifest.json and /download/app.apk -> 302 -> /cdn/app.apk.
class FakeGithub {
  late HttpServer server;
  Map<String, dynamic>? manifest;
  List<int> apk = const [];
  int apkHits = 0;
  int manifestHits = 0;

  Future<void> start() async {
    server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((req) async {
      final res = req.response;
      try {
        if (req.uri.path == '/latest/update-manifest.json') {
          manifestHits++;
          if (manifest == null) {
            res.statusCode = 404;
          } else {
            res.write(jsonEncode(manifest));
          }
        } else if (req.uri.path == '/download/app.apk') {
          res.statusCode = 302;
          res.headers.set(HttpHeaders.locationHeader, '/cdn/app.apk');
        } else if (req.uri.path == '/cdn/app.apk') {
          apkHits++;
          res.contentLength = apk.length;
          res.add(apk);
        } else {
          res.statusCode = 404;
        }
      } catch (_) {}
      await res.close().catchError((_) {});
    });
  }

  String get base => 'http://127.0.0.1:${server.port}';
  String get apkUrl => '$base/download/app.apk';
  Future<void> stop() => server.close(force: true);
}

OtaDownloader _fastNode() => OtaDownloader(
      connectTimeout: const Duration(seconds: 1),
      idleTimeout: const Duration(milliseconds: 500),
      maxAttempts: 3,
      backoff: (_) => const Duration(milliseconds: 10),
      retryChecksumMismatch: false,
    );
OtaDownloader _fastGh() => OtaDownloader(
      connectTimeout: const Duration(seconds: 1),
      idleTimeout: const Duration(milliseconds: 500),
      maxAttempts: 3,
      backoff: (_) => const Duration(milliseconds: 10),
    );

Future<int> _deadPort() async {
  final s = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final p = s.port;
  await s.close();
  return p;
}

void main() {
  late _Keys release;
  late _Keys attacker;
  late FakeNode node;
  late FakeGithub gh;
  late Directory tmp;
  final logs = <String>[];

  final apk = _payload(200000, 7);
  final sha = sha256.convert(apk).toString();

  setUpAll(() async {
    release = await _Keys.make();
    attacker = await _Keys.make();
  });

  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('ota_src_test');
    logs.clear();
    node = FakeNode()..requiredToken = 'tok-123';
    gh = FakeGithub()..apk = apk;
    await node.start();
    await gh.start();
  });

  tearDown(() async {
    await node.stop();
    await gh.stop();
    await tmp.delete(recursive: true);
  });

  OtaSourceResolver resolver({
    String? nodeBase,
    String pubkey = '',
    String? token = 'tok-123',
    bool useNode = true,
    String? githubBase,
  }) {
    final b = nodeBase ?? node.base;
    final g = githubBase ?? gh.base;
    return OtaSourceResolver(
      nodeManifestUrl: Uri.parse('$b/api/updates/manifest'),
      nodeFileBase: '$b/api/updates/file/',
      githubManifestUrls: [Uri.parse('$g/latest/update-manifest.json')],
      pubkeyHex: pubkey,
      tokenProvider: () => token,
      nodeConnectTimeout: const Duration(seconds: 1),
      nodeResponseTimeout: const Duration(seconds: 2),
      githubConnectTimeout: const Duration(seconds: 1),
      githubResponseTimeout: const Duration(seconds: 2),
      nodeDownloaderFactory: _fastNode,
      githubDownloaderFactory: _fastGh,
      log: logs.add,
      useNode: useNode,
    );
  }

  Future<OtaDownloadResult> fetchFile(OtaSourceResolver r, OtaManifestResult m, List<OtaSource> seen) {
    final e = (m.manifest['apps'] as Map)['plaza-brawler'] as Map;
    return r.download(
      githubUrl: '${e['url']}',
      sha256: '${e['sha256']}',
      dest: File('${tmp.path}/u.apk'),
      tryNode: m.nodeUsable,
      onSource: seen.add,
    );
  }

  test('valid Node manifest and file are used; GitHub file never fetched', () async {
    gh.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    node.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    node.files[sha] = apk;
    final r = resolver(pubkey: release.pubHex);
    final m = (await r.resolveManifest())!;
    expect(m.source, OtaSource.node);
    expect(m.nodeState, OtaNodeState.verified);
    final seen = <OtaSource>[];
    final d = await fetchFile(r, m, seen);
    expect(d.source, OtaSource.node);
    expect(seen, [OtaSource.node]);
    expect(await d.file.readAsBytes(), apk);
    expect(gh.apkHits, 0);
    expect(node.tokensSeen.every((t) => t == 'tok-123'), isTrue, reason: 'local token sent on every Node call');
    expect(logs.any((l) => l.contains('OTA file from node')), isTrue);
  });

  test('Node newer than GitHub: Node manifest wins', () async {
    gh.manifest = await release.sign(_manifest(1029, gh.apkUrl, sha));
    node.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    final m = (await resolver(pubkey: release.pubHex).resolveManifest())!;
    expect(m.source, OtaSource.node);
    expect(m.build, 1030);
  });

  test('Node down: GitHub manifest and file are used', () async {
    gh.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    final r = resolver(nodeBase: 'http://127.0.0.1:${await _deadPort()}', pubkey: release.pubHex);
    final m = (await r.resolveManifest())!;
    expect(m.source, OtaSource.github);
    expect(m.nodeState, OtaNodeState.unreachable);
    expect(m.nodeUsable, isFalse);
    final seen = <OtaSource>[];
    final d = await fetchFile(r, m, seen);
    expect(d.source, OtaSource.github);
    expect(seen, [OtaSource.github], reason: 'an unreachable Node is not asked again for the file');
    expect(await d.file.readAsBytes(), apk);
  });

  test('Node down, and the file step still tries it: falls back to GitHub', () async {
    gh.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    final r = resolver(nodeBase: 'http://127.0.0.1:${await _deadPort()}', pubkey: release.pubHex);
    final seen = <OtaSource>[];
    final d = await r.download(githubUrl: gh.apkUrl, sha256: sha, dest: File('${tmp.path}/u.apk'), onSource: seen.add);
    expect(seen, [OtaSource.node, OtaSource.github]);
    expect(d.source, OtaSource.github);
    expect(d.nodeFallbackReason, contains('node:'));
    expect(await d.file.readAsBytes(), apk);
  });

  test('Node manifest with a bad signature is rejected; GitHub is used', () async {
    gh.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    node.manifest = await attacker.sign(_manifest(1099, 'http://evil/app.apk', sha));
    node.files[sha] = apk;
    final r = resolver(pubkey: release.pubHex);
    final m = (await r.resolveManifest())!;
    expect(m.source, OtaSource.github);
    expect(m.build, 1030);
    expect(m.nodeState, OtaNodeState.rejected);
    final seen = <OtaSource>[];
    final d = await fetchFile(r, m, seen);
    expect(d.source, OtaSource.github);
    expect(node.fileHits, 0, reason: 'a Node with a bad manifest is not used for the file');
  });

  test('Node manifest tampered after signing (one field changed) is rejected', () async {
    gh.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    final signed = await release.sign(_manifest(1030, gh.apkUrl, sha));
    node.manifest = {...signed, 'build': 1031};
    final m = (await resolver(pubkey: release.pubHex).resolveManifest())!;
    expect(m.source, OtaSource.github);
    expect(m.nodeState, OtaNodeState.rejected);
  });

  test('unsigned Node manifest is never accepted, even when the build allows unsigned GitHub', () async {
    gh.manifest = _manifest(1030, gh.apkUrl, sha); // unsigned, accepted because no key is pinned
    node.manifest = _manifest(1031, gh.apkUrl, sha); // unsigned and newer
    final m = (await resolver(pubkey: '').resolveManifest())!;
    expect(m.source, OtaSource.github);
    expect(m.build, 1030);
    expect(m.nodeState, OtaNodeState.rejected);
  });

  test('unsigned Node manifest is rejected with a pinned key too', () async {
    gh.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    node.manifest = _manifest(1030, gh.apkUrl, sha);
    final m = (await resolver(pubkey: release.pubHex).resolveManifest())!;
    expect(m.source, OtaSource.github);
    expect(m.nodeState, OtaNodeState.rejected);
  });

  test('Node serves a wrong hash: falls back to GitHub, Node asked once (no retry on mismatch)', () async {
    gh.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    node.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    node.files[sha] = _payload(200000, 99); // wrong bytes under the right id
    final r = resolver(pubkey: release.pubHex);
    final m = (await r.resolveManifest())!;
    expect(m.source, OtaSource.node);
    final seen = <OtaSource>[];
    final d = await fetchFile(r, m, seen);
    expect(seen, [OtaSource.node, OtaSource.github]);
    expect(d.source, OtaSource.github);
    expect(d.nodeFallbackReason, contains('checksum mismatch'));
    expect(node.fileHits, 1);
    expect(await d.file.readAsBytes(), apk);
  });

  test('Node 401 (no token): GitHub manifest and file are used', () async {
    gh.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    node.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    node.files[sha] = apk;
    final r = resolver(pubkey: release.pubHex, token: null);
    final m = (await r.resolveManifest())!;
    expect(m.source, OtaSource.github);
    expect(m.nodeState, OtaNodeState.unauthorized);
    expect(m.detail, contains('no local token'));
    final d = await fetchFile(r, m, <OtaSource>[]);
    expect(d.source, OtaSource.github);
    expect(node.tokensSeen.every((t) => t == null), isTrue);
  });

  test('Node 401 (wrong token) is reported as refused', () async {
    gh.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    node.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    final m = (await resolver(pubkey: release.pubHex, token: 'nope').resolveManifest())!;
    expect(m.source, OtaSource.github);
    expect(m.detail, contains('token refused'));
  });

  test('Node file answers 401 / 403 / 404: each falls back to GitHub at once', () async {
    for (final code in [401, 403, 404]) {
      node.fileHits = 0;
      node.fileStatus = code;
      final r = resolver(pubkey: release.pubHex);
      final seen = <OtaSource>[];
      final d = await r.download(githubUrl: gh.apkUrl, sha256: sha, dest: File('${tmp.path}/u$code.apk'), onSource: seen.add);
      expect(d.source, OtaSource.github, reason: 'HTTP $code');
      expect(d.nodeFallbackReason, contains('HTTP $code'));
      expect(node.fileHits, 1, reason: 'no retry on HTTP $code');
      expect(await d.file.readAsBytes(), apk);
    }
  });

  test('Node manifest older than GitHub: GitHub manifest is used', () async {
    gh.manifest = await release.sign(_manifest(1031, gh.apkUrl, sha));
    node.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    final m = (await resolver(pubkey: release.pubHex).resolveManifest())!;
    expect(m.source, OtaSource.github);
    expect(m.build, 1031);
    expect(m.detail, contains('older'));
  });

  test('GitHub unreachable: a verified Node manifest alone is used', () async {
    node.manifest = await release.sign(_manifest(1030, 'https://github.invalid/app.apk', sha));
    node.files[sha] = apk;
    final r = resolver(pubkey: release.pubHex, githubBase: 'http://127.0.0.1:${await _deadPort()}');
    final m = (await r.resolveManifest())!;
    expect(m.source, OtaSource.node);
    expect(m.detail, contains('GitHub unreachable'));
    final d = await fetchFile(r, m, <OtaSource>[]);
    expect(d.source, OtaSource.node);
    expect(await d.file.readAsBytes(), apk);
  });

  test('GitHub unreachable and Node unsigned: no manifest at all', () async {
    node.manifest = _manifest(1030, gh.apkUrl, sha);
    expect(await resolver(pubkey: release.pubHex, githubBase: 'http://127.0.0.1:${await _deadPort()}').resolveManifest(), isNull);
  });

  test('Node 404 (no manifest yet): GitHub is used', () async {
    gh.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    final m = (await resolver(pubkey: release.pubHex).resolveManifest())!;
    expect(m.source, OtaSource.github);
    expect(m.nodeState, OtaNodeState.noManifest);
  });

  test('useNode: false behaves like 0.1.2 (GitHub only, Node never contacted)', () async {
    gh.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    node.manifest = await release.sign(_manifest(1030, gh.apkUrl, sha));
    node.files[sha] = apk;
    final r = resolver(pubkey: release.pubHex, useNode: false);
    final m = (await r.resolveManifest())!;
    expect(m.source, OtaSource.github);
    final d = await r.download(githubUrl: gh.apkUrl, sha256: sha, dest: File('${tmp.path}/u.apk'));
    expect(d.source, OtaSource.github);
    expect(node.manifestHits + node.fileHits, 0);
  });

  test('isTrusted matches 0.1.2 manifestTrusted semantics', () async {
    final signed = await release.sign(_manifest(1030, 'u', sha));
    expect(await OtaSourceResolver.isTrusted(signed, release.pubHex), isTrue);
    expect(await OtaSourceResolver.isTrusted(signed, attacker.pubHex), isFalse);
    expect(await OtaSourceResolver.isTrusted(_manifest(1030, 'u', sha), release.pubHex), isFalse);
    expect(await OtaSourceResolver.isTrusted(_manifest(1030, 'u', sha), ''), isTrue);
    expect(await OtaSourceResolver.isTrusted(_manifest(1030, 'u', sha), '', requireSignature: true), isFalse);
  });

  test('a cancel during the Node download does not fall through to GitHub', () async {
    node.files[sha] = apk;
    // slow Node: a server that accepts and never answers
    final hang = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    hang.listen((_) {});
    final r = OtaSourceResolver(
      nodeManifestUrl: Uri.parse('http://127.0.0.1:${hang.port}/api/updates/manifest'),
      nodeFileBase: 'http://127.0.0.1:${hang.port}/api/updates/file/',
      githubManifestUrls: [Uri.parse('${gh.base}/latest/update-manifest.json')],
      nodeDownloaderFactory: () => OtaDownloader(idleTimeout: const Duration(seconds: 10), retryChecksumMismatch: false),
      githubDownloaderFactory: _fastGh,
      log: logs.add,
    );
    final f = r.download(githubUrl: gh.apkUrl, sha256: sha, dest: File('${tmp.path}/c.apk'));
    await Future<void>.delayed(const Duration(milliseconds: 200));
    r.cancel();
    await expectLater(f, throwsA(isA<OtaDownloadException>()));
    expect(gh.apkHits, 0);
    await hang.close(force: true);
  });
}

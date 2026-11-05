import 'dart:async';
import 'dart:convert';
import 'dart:developer' as developer;
import 'dart:io';

import 'package:cryptography/cryptography.dart';

import 'canonical_json.dart';
import 'ota_download.dart';

/// ============================================================================
/// OTA SOURCES (omni_core_ui 0.1.3), pure Dart
/// ============================================================================
/// Where an update comes from: the Omni Node on this phone first, GitHub
/// Releases second.
///
/// Omni-Daemon v8.30.0 keeps a verified copy of the release manifest and of the
/// files it lists (Admin/docs/PEER_UPDATES.md), on loopback :5000:
///   GET /api/updates/manifest        the manifest exactly as signed
///   GET /api/updates/file/<sha256>   the file (Range; cache, paired peer, GitHub)
/// Both need the Node's local token when it runs with OMNI_LOCAL_TOKEN=1 (Omni
/// Node always does); it is sent as "X-Omni-Local-Token".
///
/// Trust does not move to the Node:
/// * The Node's manifest is used only if its Ed25519 signature verifies against
///   the pinned key, exactly as a GitHub manifest is checked. With no pinned key
///   (unsigned builds) the Node's manifest is never used: an unsigned manifest
///   is only ever accepted from GitHub over HTTPS.
/// * It must not be older (lower `build`) than GitHub's. If GitHub can't be
///   reached, a verified Node manifest alone is enough.
/// * Files are fetched by the SHA-256 from the chosen manifest and checked by
///   [OtaDownloader]; any failure (no Node, 401/403/404, a wrong hash, a stall)
///   falls back to the manifest's GitHub URL with the usual retries.
/// ============================================================================

/// Where a manifest or file came from.
enum OtaSource {
  /// The Omni Node (daemon) on this phone, 127.0.0.1:5000.
  node,

  /// GitHub Releases.
  github,
}

extension OtaSourceLabel on OtaSource {
  /// Short words for status text.
  String get label => this == OtaSource.node ? 'Omni Node on this phone' : 'GitHub';
}

/// What the Node said when asked for the manifest.
enum OtaNodeState {
  /// Not asked (no Node URL configured).
  skipped,

  /// Nothing listening, or it timed out.
  unreachable,

  /// 401/403: the local token is missing or wrong.
  unauthorized,

  /// It answered, but with no manifest (404: none yet; 409: updates off; other).
  noManifest,

  /// It sent a manifest whose signature didn't verify (or no key is pinned).
  rejected,

  /// A verified manifest.
  verified,
}

/// The manifest chosen by [OtaSourceResolver.resolveManifest].
class OtaManifestResult {
  final Map<String, dynamic> manifest;
  final OtaSource source;
  final OtaNodeState nodeState;

  /// One line on how it was chosen, for logs.
  final String detail;

  const OtaManifestResult(this.manifest, this.source, this.nodeState, this.detail);

  int get build => OtaSourceResolver.buildOf(manifest);

  /// True when the Node is worth asking for the file: it answered with a
  /// verified manifest (the file id comes from the chosen manifest either way).
  bool get nodeUsable => nodeState == OtaNodeState.verified;
}

/// Result of [OtaSourceResolver.download].
class OtaDownloadResult {
  final File file;
  final OtaSource source;

  /// Why the Node wasn't used, when it wasn't (null when it was).
  final String? nodeFallbackReason;

  const OtaDownloadResult(this.file, this.source, this.nodeFallbackReason);
}

class OtaSourceResolver {
  /// Default Node endpoints (daemon v8.30.0+).
  static final Uri defaultNodeManifestUrl = Uri.parse('http://127.0.0.1:5000/api/updates/manifest');
  static const String defaultNodeFileBase = 'http://127.0.0.1:5000/api/updates/file/';

  static const String localTokenHeader = 'X-Omni-Local-Token';

  /// Null: don't ask the Node.
  final Uri? nodeManifestUrl;

  /// Prefix the file's SHA-256 is appended to. Null: don't download from the Node.
  final String? nodeFileBase;

  final List<Uri> githubManifestUrls;

  /// 64-hex Ed25519 key that must sign the manifest. Empty: GitHub manifests
  /// are accepted unsigned (as before) and the Node's are never used.
  final String pubkeyHex;

  /// Returns the Node's local token, or null/empty when there is none.
  final FutureOr<String?> Function()? tokenProvider;

  final Duration nodeConnectTimeout;

  /// The Node may refresh from GitHub before it answers, so it gets longer than
  /// the connect timeout; if it is slower than this, GitHub's copy is used.
  final Duration nodeResponseTimeout;
  final Duration githubConnectTimeout;
  final Duration githubResponseTimeout;

  /// Downloaders; defaults are made per [download] call.
  final OtaDownloader Function() nodeDownloaderFactory;
  final OtaDownloader Function() githubDownloaderFactory;

  final void Function(String message) log;

  OtaSourceResolver({
    Uri? nodeManifestUrl,
    String? nodeFileBase = defaultNodeFileBase,
    required this.githubManifestUrls,
    this.pubkeyHex = '',
    this.tokenProvider,
    this.nodeConnectTimeout = const Duration(seconds: 3),
    this.nodeResponseTimeout = const Duration(seconds: 12),
    this.githubConnectTimeout = const Duration(seconds: 6),
    this.githubResponseTimeout = const Duration(seconds: 10),
    OtaDownloader Function()? nodeDownloaderFactory,
    OtaDownloader Function()? githubDownloaderFactory,
    void Function(String message)? log,
    bool useNode = true,
  })  : nodeManifestUrl = useNode ? (nodeManifestUrl ?? defaultNodeManifestUrl) : null,
        nodeFileBase = useNode ? nodeFileBase : null,
        nodeDownloaderFactory = nodeDownloaderFactory ??
            (() => OtaDownloader(
                  connectTimeout: const Duration(seconds: 3),
                  maxAttempts: 3,
                  retryChecksumMismatch: false,
                )),
        githubDownloaderFactory = githubDownloaderFactory ?? (() => OtaDownloader()),
        log = log ?? ((m) => developer.log(m, name: 'omni_ota'));

  final List<OtaDownloader> _active = [];
  bool _cancelled = false;

  /// Stops a [download] in progress; it then throws [OtaDownloadException].
  void cancel() {
    _cancelled = true;
    for (final d in List.of(_active)) {
      d.cancel();
    }
  }

  /// The manifest's `build` as an int (0 when missing or odd).
  static int buildOf(Map<String, dynamic> m) {
    final b = m['build'];
    if (b is int) return b;
    return int.tryParse('$b') ?? 0;
  }

  /// True when [manifest] carries a signature by [pubkeyHex] (Ed25519 over the
  /// canonical JSON of the manifest minus "signature"). With an empty key:
  /// true unless [requireSignature], which is how the Node's copy is treated.
  static Future<bool> isTrusted(
    Map<String, dynamic> manifest,
    String pubkeyHex, {
    bool requireSignature = false,
  }) async {
    if (pubkeyHex.isEmpty) return !requireSignature;
    final sig = manifest['signature'];
    if (sig is! String) return false;
    final unsigned = Map<String, dynamic>.from(manifest)..remove('signature');
    return verifyEd25519(utf8.encode(canonicalJson(unsigned)), sig, pubkeyHex);
  }

  static Future<bool> verifyEd25519(List<int> message, String signatureHex, String pubkeyHex) async {
    try {
      final pub = _unhex(pubkeyHex);
      final sig = _unhex(signatureHex);
      if (pub.length != 32 || sig.length != 64) return false;
      return await Ed25519().verify(
        message,
        signature: Signature(sig, publicKey: SimplePublicKey(pub, type: KeyPairType.ed25519)),
      );
    } catch (_) {
      return false;
    }
  }

  static List<int> _unhex(String h) {
    final s = h.trim();
    if (s.length.isOdd) throw const FormatException('odd hex');
    return [for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16)];
  }

  Future<String?> _token() async {
    final p = tokenProvider;
    if (p == null) return null;
    try {
      final t = (await p())?.trim();
      return (t == null || t.isEmpty) ? null : t;
    } catch (_) {
      return null;
    }
  }

  Future<({int status, Map<String, dynamic>? body})> _getJson(
    Uri url,
    Duration connect,
    Duration response, {
    Map<String, String>? headers,
  }) async {
    final client = HttpClient()
      ..connectionTimeout = connect
      ..userAgent = 'omni-ota/1';
    if (url.host == '127.0.0.1' || url.host == 'localhost' || url.host == '::1') {
      client.findProxy = (_) => 'DIRECT'; // the Node is never behind a proxy
    }
    try {
      final req = await client.getUrl(url).timeout(connect);
      headers?.forEach(req.headers.set);
      final res = await req.close().timeout(response);
      final text = await res.transform(utf8.decoder).join().timeout(response);
      if (res.statusCode != 200) return (status: res.statusCode, body: null);
      final decoded = jsonDecode(text);
      return (status: 200, body: decoded is Map<String, dynamic> ? decoded : null);
    } finally {
      client.close(force: true);
    }
  }

  Future<({OtaNodeState state, Map<String, dynamic>? manifest, String detail})> _fromNode() async {
    final url = nodeManifestUrl;
    if (url == null) return (state: OtaNodeState.skipped, manifest: null, detail: 'node not asked');
    final token = await _token();
    try {
      final r = await _getJson(url, nodeConnectTimeout, nodeResponseTimeout,
          headers: token == null ? null : {localTokenHeader: token});
      if (r.status == 401 || r.status == 403) {
        return (
          state: OtaNodeState.unauthorized,
          manifest: null,
          detail: 'node said HTTP ${r.status}${token == null ? ' (no local token set)' : ' (token refused)'}',
        );
      }
      if (r.status != 200 || r.body == null) {
        return (state: OtaNodeState.noManifest, manifest: null, detail: 'node said HTTP ${r.status}');
      }
      if (pubkeyHex.isEmpty) {
        return (state: OtaNodeState.rejected, manifest: null, detail: 'node manifest ignored: no pinned key in this build');
      }
      if (!await isTrusted(r.body!, pubkeyHex, requireSignature: true)) {
        return (state: OtaNodeState.rejected, manifest: null, detail: 'node manifest rejected: bad or missing signature');
      }
      return (state: OtaNodeState.verified, manifest: r.body, detail: 'node manifest verified');
    } catch (e) {
      return (state: OtaNodeState.unreachable, manifest: null, detail: 'node unreachable (${e.runtimeType})');
    }
  }

  Future<Map<String, dynamic>?> _fromGithub() async {
    for (final src in githubManifestUrls) {
      try {
        final r = await _getJson(src, githubConnectTimeout, githubResponseTimeout);
        if (r.body != null && await isTrusted(r.body!, pubkeyHex)) return r.body;
      } catch (_) {
        // try the next source
      }
    }
    return null;
  }

  /// Asks the Node and GitHub at the same time and picks one (see the header).
  /// Null when neither has a manifest this build trusts.
  Future<OtaManifestResult?> resolveManifest() async {
    final nodeF = _fromNode();
    final ghF = _fromGithub();
    final node = await nodeF;
    final gh = await ghF;
    final OtaManifestResult? out;
    if (node.manifest != null && gh != null) {
      final nb = buildOf(node.manifest!), gb = buildOf(gh);
      out = nb >= gb
          ? OtaManifestResult(node.manifest!, OtaSource.node, node.state, 'node build $nb >= GitHub build $gb')
          : OtaManifestResult(gh, OtaSource.github, node.state, 'node build $nb older than GitHub build $gb');
    } else if (node.manifest != null) {
      out = OtaManifestResult(node.manifest!, OtaSource.node, node.state, 'GitHub unreachable; ${node.detail}');
    } else if (gh != null) {
      out = OtaManifestResult(gh, OtaSource.github, node.state, node.detail);
    } else {
      out = null;
    }
    log(out == null
        ? 'OTA manifest: none trusted (${node.detail}; GitHub gave nothing usable)'
        : 'OTA manifest from ${out.source.name}, build ${out.build} (${out.detail})');
    return out;
  }

  static final RegExp _sha = RegExp(r'^[0-9a-f]{64}$');

  /// Downloads into [dest]: from the Node by [sha256] when [tryNode] and the
  /// Node is configured, else (or on any Node failure) from [githubUrl].
  /// [onSource] is told each source as it starts. Throws
  /// [OtaDownloadException] when GitHub fails too, or on [cancel].
  Future<OtaDownloadResult> download({
    required String githubUrl,
    required File dest,
    String? sha256,
    bool tryNode = true,
    OtaProgress? onProgress,
    void Function(OtaSource source)? onSource,
  }) async {
    final want = (sha256 ?? '').trim().toLowerCase();
    String? reason;
    final base = nodeFileBase;
    if (!tryNode) {
      reason = 'node not usable';
    } else if (base == null) {
      reason = 'node not configured';
    } else if (!_sha.hasMatch(want)) {
      reason = 'manifest has no SHA-256 for this app';
    } else {
      final token = await _token();
      final d = nodeDownloaderFactory();
      _active.add(d);
      try {
        if (_cancelled) throw OtaDownloadException('cancelled', retryable: false);
        onSource?.call(OtaSource.node);
        final f = await d.download(
          Uri.parse('$base$want'),
          dest,
          sha256: want,
          onProgress: onProgress,
          headers: token == null ? null : {localTokenHeader: token},
        );
        log('OTA file from node (${f.lengthSync()} bytes, sha256 ok)');
        return OtaDownloadResult(f, OtaSource.node, null);
      } on OtaDownloadException catch (e) {
        if (_cancelled) rethrow;
        reason = 'node: $e';
      } catch (e) {
        if (_cancelled) throw OtaDownloadException('cancelled', retryable: false);
        reason = 'node: $e';
      } finally {
        _active.remove(d);
      }
    }
    log('OTA file from GitHub ($reason)');
    if (_cancelled) throw OtaDownloadException('cancelled', retryable: false);
    final g = githubDownloaderFactory();
    _active.add(g);
    try {
      onSource?.call(OtaSource.github);
      final f = await g.download(Uri.parse(githubUrl), dest, sha256: sha256, onProgress: onProgress);
      return OtaDownloadResult(f, OtaSource.github, reason);
    } finally {
      _active.remove(g);
    }
  }
}

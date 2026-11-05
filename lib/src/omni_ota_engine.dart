import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:ota_update/ota_update.dart';

import 'ota_download.dart';
import 'ota_sources.dart';

/// ============================================================================
/// OMNI OTA ENGINE (omni_core_ui)
/// ============================================================================
/// In-app over-the-air updates for every Omniverse APK.
///
/// Today the update source is GitHub Releases (free hosting). Every tagged
/// release publishes `update-manifest.json`:
///   { "tag": "v0.1.3", "build": 1012, "transport": "github",
///     "apps": { "mesh-monitor": { "url": "...apk", "sha256": "..." }, ... } }
///
/// The app compares the manifest `build` with its own build number (baked in at
/// compile time with --dart-define=OMNI_BUILD=...). If newer, it offers the
/// update, downloads the APK, verifies its SHA-256 and opens Android's install
/// prompt. Releases share one signing key, so the update installs over the top.
///
/// Signed manifests: when the release workflow has the OMNI_OTA_SIGNING_KEY
/// secret, it signs the manifest (Ed25519 over the canonical JSON of the
/// manifest minus "signature") and bakes the public key into every APK with
/// --dart-define=OMNI_OTA_PUBKEY=<hex>. A build that has a public key refuses
/// any manifest that isn't signed by it. That matters most once peers serve
/// updates over OmniNet, since a peer is not trusted the way GitHub is.
///
/// Local Node first (0.1.3): Omni-Daemon v8.30.0+ keeps a verified copy of the
/// manifest and the files, shared between paired devices. The app asks the Node
/// on 127.0.0.1:5000 first and GitHub at the same time; the Node's manifest is
/// used only if its signature verifies against [otaPubkey] (never unsigned) and
/// it isn't older than GitHub's. The file comes from the Node by SHA-256 when it
/// can, else from GitHub. Omni Node needs its local token: apps hand it over
/// with [OmniOta.localTokenProvider] (or `localToken:` on [checkAndPrompt]).
/// Details: ota_sources.dart, and Omni-Daemon Admin/docs/PEER_UPDATES.md.
/// ============================================================================

class OmniOta {
  /// Short app name, matching the release asset (e.g. "mesh-monitor").
  static const String appSlug = String.fromEnvironment('OMNI_APP', defaultValue: 'unknown');

  /// This build's number (1000 + release workflow run). 0 = local dev build.
  static const int currentBuild = int.fromEnvironment('OMNI_BUILD', defaultValue: 0);

  /// GitHub manifest URLs, in priority order (the Node is asked at
  /// [nodeManifestUrl] ahead of these, see [localNodeFirst]).
  static const List<String> manifestSources = [
    'https://github.com/kiroba/The-Omniverse/releases/latest/download/update-manifest.json',
  ];

  /// Ed25519 public key (64 hex) that must sign the manifest. Empty = unsigned
  /// manifests accepted (HTTPS + SHA-256 only).
  static const String otaPubkey = String.fromEnvironment('OMNI_OTA_PUBKEY', defaultValue: '');

  /// The Omni Node's loopback manifest (daemon v8.30.0+).
  static const String nodeManifestUrl = 'http://127.0.0.1:5000/api/updates/manifest';

  /// The Omni Node's file endpoint; the file's SHA-256 is appended.
  static const String nodeFileUrlBase = 'http://127.0.0.1:5000/api/updates/file/';

  /// Ask the local Omni Node before GitHub (default on). Set false to go
  /// straight to GitHub as in 0.1.2.
  static bool localNodeFirst = true;

  /// Returns the Omni Node local token (Omni Node > Connect apps), or null when
  /// the app has none. Default: none, so on a Node that requires the token
  /// (Omni Node always does) the Node answers 401 and GitHub is used. Apps that
  /// already keep the token set this once, e.g.
  /// `OmniOta.localTokenProvider = () => node.token;`.
  static FutureOr<String?> Function()? localTokenProvider;

  /// Where the last manifest and the last download came from (null before).
  static OtaSource? get lastManifestSource => _lastManifest?.source;
  static OtaSource? get lastDownloadSource => _lastDownloadSource;

  static bool _checkedThisSession = false;
  static OtaManifestResult? _lastManifest;
  static OtaSource? _lastDownloadSource;

  /// True when the manifest's signature checks out, or no key is pinned.
  static Future<bool> manifestTrusted(Map<String, dynamic> manifest) =>
      OtaSourceResolver.isTrusted(manifest, otaPubkey);

  static OtaSourceResolver _resolver(String? localToken) => OtaSourceResolver(
        nodeManifestUrl: Uri.parse(nodeManifestUrl),
        nodeFileBase: nodeFileUrlBase,
        githubManifestUrls: [for (final s in manifestSources) Uri.parse(s)],
        pubkeyHex: otaPubkey,
        tokenProvider: (localToken != null && localToken.trim().isNotEmpty)
            ? () => localToken
            : localTokenProvider,
        useNode: localNodeFirst,
        log: (m) => debugPrint('[omni_ota] $m'),
      );

  /// The manifest to use: the local Omni Node's when it is signed and not older
  /// than GitHub's, else GitHub's. Returns null if neither answers with one this
  /// build trusts. [localToken] overrides [localTokenProvider].
  static Future<Map<String, dynamic>?> fetchManifest({String? localToken}) async {
    final r = await _resolver(localToken).resolveManifest();
    _lastManifest = r;
    return r?.manifest;
  }

  /// Checks for an update and, if one exists, asks the user to install it.
  /// [silent]: no message when already up to date or offline (use on startup).
  /// [localToken]: the Omni Node local token, if the caller has it at hand
  /// (otherwise [localTokenProvider] is asked).
  static Future<void> checkAndPrompt(BuildContext context, {bool silent = false, String? localToken}) async {
    if (silent && _checkedThisSession) return;
    _checkedThisSession = true;

    // In-app updates install APKs (ota_update is Android-only). Desktop builds
    // update by downloading the new zip from GitHub Releases.
    if (!Platform.isAndroid) {
      if (!silent) {
        ScaffoldMessenger.maybeOf(context)?.showSnackBar(const SnackBar(
          content: Text('In-app updates are Android-only. Get the new build from GitHub Releases.'),
        ));
      }
      return;
    }

    final messenger = ScaffoldMessenger.maybeOf(context);
    final manifest = await fetchManifest(localToken: localToken);
    final fromNode = _lastManifest?.nodeUsable ?? false;
    if (manifest == null) {
      if (!silent) messenger?.showSnackBar(const SnackBar(content: Text('Could not reach the update server.')));
      return;
    }

    final latestBuild = (manifest['build'] is int) ? manifest['build'] as int : int.tryParse('${manifest['build']}') ?? 0;
    final apps = manifest['apps'];
    final entry = (apps is Map) ? apps[appSlug] : null;
    final tag = '${manifest['tag'] ?? ''}';

    if (entry is! Map || entry['url'] == null || latestBuild <= currentBuild) {
      if (!silent) {
        messenger?.showSnackBar(SnackBar(
          content: Text(currentBuild == 0
              ? 'Dev build: updates are only checked on release builds.'
              : 'You are up to date ($tag).'),
        ));
      }
      return;
    }
    if (currentBuild == 0) return; // never auto-replace a local dev build

    if (!context.mounted) return;
    final accept = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        scrollable: true,
        title: const Text('Update available'),
        content: Text('Omniverse $tag (build $latestBuild) is ready.\n'
            'You have build $currentBuild.\n'
            'Found via ${(_lastManifest?.source ?? OtaSource.github).label}.\n\n'
            'It downloads, gets checked (SHA-256), then Android asks you to install.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Later')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Update')),
        ],
      ),
    );
    if (accept != true || !context.mounted) return;

    _runUpdate(context, '${entry['url']}', entry['sha256']?.toString(),
        tryNode: fromNode, localToken: localToken);
  }

  static void _runUpdate(BuildContext context, String url, String? sha256,
      {bool tryNode = false, String? localToken}) {
    final progress = ValueNotifier<String>('Starting download...');
    final resolver = _resolver(localToken);
    final maxTries = {
      OtaSource.node: resolver.nodeDownloaderFactory().maxAttempts,
      OtaSource.github: resolver.githubDownloaderFactory().maxAttempts,
    };
    var source = OtaSource.github;
    LoopbackFileServer? local;
    var closed = false;
    void finish() {
      closed = true;
      resolver.cancel();
      OtaUpdate().cancel();
      local?.close();
    }

    showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        scrollable: true,
        title: const Text('Updating'),
        content: ValueListenableBuilder<String>(
          valueListenable: progress,
          builder: (_, value, __) => Text(value),
        ),
        actions: [
          TextButton(
            onPressed: () {
              finish();
              Navigator.pop(ctx);
            },
            child: const Text('Close'),
          ),
        ],
      ),
    );

    // 1) Download in Dart: long idle timeout, retries that resume, SHA-256 check.
    // 2) Hand the verified file to the installer plugin from 127.0.0.1, so its
    //    fixed 10 s network timeout never meets the internet.
    () async {
      try {
        final dir = await Directory.systemTemp.createTemp('omni_ota');
        final file = File('${dir.path}/$appSlug-update.apk');
        final result = await resolver.download(
          githubUrl: url,
          dest: file,
          sha256: sha256,
          tryNode: tryNode,
          onSource: (s) {
            source = s;
            if (!closed) progress.value = 'Downloading from ${s.label}...';
          },
          onProgress: (got, total, attempt) {
            if (closed) return;
            final pct = total == null || total == 0
                ? ''
                : ' ${(got * 100 ~/ total)}%';
            final mb = (got / 1048576).toStringAsFixed(1);
            progress.value =
                'Downloading from ${source.label}...$pct ($mb MB)${attempt > 1 ? '\nSlow connection: try $attempt of ${maxTries[source]}' : ''}';
          },
        );
        _lastDownloadSource = result.source;
        if (closed) return;
        progress.value =
            'Downloaded from ${result.source.label} and checked. Opening the Android installer...';
        local = await LoopbackFileServer.serve(file, '$appSlug-update.apk');
        OtaUpdate()
            .execute(
              local!.url.toString(),
              destinationFilename: '$appSlug-update.apk',
              sha256checksum: (sha256 == null || sha256.isEmpty)
                  ? null
                  : sha256,
            )
            .listen(
              (OtaEvent event) {
                if (closed) return;
                switch (event.status) {
                  case OtaStatus.DOWNLOADING:
                    break; // local copy, instant
                  case OtaStatus.INSTALLING:
                    progress.value =
                        'Verified. Opening the Android installer...';
                    break;
                  case OtaStatus.CHECKSUM_ERROR:
                    progress.value =
                        'Checksum mismatch: the download was rejected.';
                    break;
                  case OtaStatus.PERMISSION_NOT_GRANTED_ERROR:
                    progress.value = 'Allow "Install unknown apps" for this app, then try again.';
                    break;
                  default:
                    progress.value =
                        'Update stopped: ${event.status.name}${event.value == null ? '' : ' (${event.value})'}';
                }
              },
              onError: (Object e) {
                if (!closed) progress.value = 'Update failed: $e';
              },
            );
      } on OtaDownloadException catch (e) {
        if (!closed) {
          progress.value =
              'Could not download the update ($e). '
              'Check your connection and tap Update again, or get it from the tester page.';
        }
      } catch (e) {
        if (!closed) progress.value = 'Update failed: $e';
      }
    }();
  }
}

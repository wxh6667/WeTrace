import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart' as p;

typedef _InitializeHookNative = Bool Function(Uint32 targetPid);
typedef _InitializeHookDart = bool Function(int targetPid);
typedef _PollKeyDataNative = Bool Function(Pointer<Int8> keyBuffer, Int32 size);
typedef _PollKeyDataDart = bool Function(Pointer<Int8> keyBuffer, int size);
typedef _CleanupHookNative = Bool Function();
typedef _CleanupHookDart = bool Function();
typedef _GetLastErrorMsgNative = Pointer<Int8> Function();
typedef _GetLastErrorMsgDart = Pointer<Int8> Function();

class WxKeyService {
  DynamicLibrary? _library;
  _InitializeHookDart? _initializeHook;
  _PollKeyDataDart? _pollKeyData;
  _CleanupHookDart? _cleanupHook;
  _GetLastErrorMsgDart? _getLastErrorMsg;

  Future<String?> fetchDecryptKey({
    Duration timeout = const Duration(seconds: 12),
  }) async {
    if (!Platform.isWindows) return null;

    final pid = await _findWeixinPid();
    if (pid == null) return null;

    _loadLibrary();
    final initializeHook = _initializeHook;
    final pollKeyData = _pollKeyData;
    final cleanupHook = _cleanupHook;
    if (initializeHook == null || pollKeyData == null || cleanupHook == null) {
      return null;
    }

    if (!initializeHook(pid)) {
      return null;
    }

    final keyBuffer = calloc<Int8>(128);
    try {
      final deadline = DateTime.now().add(timeout);
      while (DateTime.now().isBefore(deadline)) {
        if (pollKeyData(keyBuffer, 128)) {
          final key = _readNullTerminated(keyBuffer.cast<Uint8>());
          if (RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(key)) {
            return key;
          }
        }
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
      return null;
    } finally {
      calloc.free(keyBuffer);
      cleanupHook();
    }
  }

  String getLastErrorMessage() {
    final getLastErrorMsg = _getLastErrorMsg;
    if (getLastErrorMsg == null) return '';

    final ptr = getLastErrorMsg();
    if (ptr == nullptr) return '';
    return _readNullTerminated(ptr.cast<Uint8>());
  }

  void _loadLibrary() {
    if (_library != null) return;

    final exeDir = File(Platform.resolvedExecutable).parent.path;
    final assetDllPath = p.join(
      exeDir,
      'data',
      'flutter_assets',
      'assets',
      'dll',
      'wx_key.dll',
    );
    final candidates = <String>[
      assetDllPath,
      p.join(exeDir, 'wx_key.dll'),
      p.join(exeDir, 'data', 'wx_key.dll'),
    ];

    Object? lastError;
    for (final candidate in candidates) {
      try {
        _library = DynamicLibrary.open(candidate);
        _bindFunctions();
        return;
      } catch (e) {
        _library = null;
        lastError = e;
      }
    }

    throw UnsupportedError('Failed to load wx_key.dll: $lastError');
  }

  void _bindFunctions() {
    final library = _library!;
    _initializeHook = library
        .lookup<NativeFunction<_InitializeHookNative>>('InitializeHook')
        .asFunction();
    _pollKeyData = library
        .lookup<NativeFunction<_PollKeyDataNative>>('PollKeyData')
        .asFunction();
    _cleanupHook = library
        .lookup<NativeFunction<_CleanupHookNative>>('CleanupHook')
        .asFunction();
    _getLastErrorMsg = library
        .lookup<NativeFunction<_GetLastErrorMsgNative>>('GetLastErrorMsg')
        .asFunction();
  }

  Future<int?> _findWeixinPid() async {
    final result = await Process.run(
      'tasklist',
      ['/FI', 'IMAGENAME eq Weixin.exe', '/FO', 'CSV', '/NH'],
      runInShell: true,
    );
    if (result.exitCode != 0) return null;

    final output = result.stdout?.toString() ?? '';
    for (final line in const LineSplitter().convert(output)) {
      final columns = _parseCsvLine(line);
      if (columns.length < 2) continue;
      if (columns.first.toLowerCase() != 'weixin.exe') continue;
      return int.tryParse(columns[1]);
    }
    return null;
  }

  List<String> _parseCsvLine(String line) {
    final values = <String>[];
    final buffer = StringBuffer();
    var quoted = false;

    for (var i = 0; i < line.length; i++) {
      final char = line[i];
      if (char == '"') {
        quoted = !quoted;
      } else if (char == ',' && !quoted) {
        values.add(buffer.toString());
        buffer.clear();
      } else {
        buffer.write(char);
      }
    }
    values.add(buffer.toString());
    return values.map((value) => value.trim()).toList();
  }

  String _readNullTerminated(Pointer<Uint8> ptr) {
    final bytes = <int>[];
    for (var offset = 0; ; offset++) {
      final byte = ptr.elementAt(offset).value;
      if (byte == 0) break;
      bytes.add(byte);
    }
    return latin1.decode(bytes).trim();
  }
}

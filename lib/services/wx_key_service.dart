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
typedef _GetStatusMessageNative =
    Bool Function(Pointer<Int8> statusBuffer, Int32 size, Pointer<Int32> level);
typedef _GetStatusMessageDart =
    bool Function(Pointer<Int8> statusBuffer, int size, Pointer<Int32> level);
typedef _GetLastErrorMsgNative = Pointer<Int8> Function();
typedef _GetLastErrorMsgDart = Pointer<Int8> Function();

typedef _EnumWindowsProcNative = Int32 Function(IntPtr hwnd, IntPtr lParam);
typedef _EnumWindowsNative =
    Int32 Function(
      Pointer<NativeFunction<_EnumWindowsProcNative>> callback,
      IntPtr lParam,
    );
typedef _EnumWindowsDart =
    int Function(
      Pointer<NativeFunction<_EnumWindowsProcNative>> callback,
      int lParam,
    );
typedef _IsWindowVisibleNative = Int32 Function(IntPtr hwnd);
typedef _IsWindowVisibleDart = int Function(int hwnd);
typedef _GetWindowThreadProcessIdNative =
    Uint32 Function(IntPtr hwnd, Pointer<Uint32> processId);
typedef _GetWindowThreadProcessIdDart =
    int Function(int hwnd, Pointer<Uint32> processId);
typedef _OpenProcessNative =
    IntPtr Function(Uint32 desiredAccess, Int32 inheritHandle, Uint32 processId);
typedef _OpenProcessDart =
    int Function(int desiredAccess, int inheritHandle, int processId);
typedef _QueryFullProcessImageNameNative =
    Int32 Function(
      IntPtr process,
      Uint32 flags,
      Pointer<Utf16> exeName,
      Pointer<Uint32> size,
    );
typedef _QueryFullProcessImageNameDart =
    int Function(
      int process,
      int flags,
      Pointer<Utf16> exeName,
      Pointer<Uint32> size,
    );
typedef _CloseHandleNative = Int32 Function(IntPtr handle);
typedef _CloseHandleDart = int Function(int handle);

class WxKeyService {
  static const int _processQueryLimitedInformation = 0x1000;
  static final Set<int> _windowProcessIds = <int>{};
  static _IsWindowVisibleDart? _isWindowVisibleForCallback;
  static _GetWindowThreadProcessIdDart? _getWindowThreadProcessIdForCallback;

  DynamicLibrary? _library;
  _InitializeHookDart? _initializeHook;
  _PollKeyDataDart? _pollKeyData;
  _CleanupHookDart? _cleanupHook;
  _GetStatusMessageDart? _getStatusMessage;
  _GetLastErrorMsgDart? _getLastErrorMsg;
  String _lastStatusMessage = '';

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
      _drainStatusMessages();
      return null;
    }

    final keyBuffer = calloc<Int8>(128);
    try {
      final deadline = DateTime.now().add(timeout);
      while (DateTime.now().isBefore(deadline)) {
        _drainStatusMessages();
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
    _drainStatusMessages();
    if (_lastStatusMessage.isNotEmpty) return _lastStatusMessage;

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
    _getStatusMessage = library
        .lookup<NativeFunction<_GetStatusMessageNative>>('GetStatusMessage')
        .asFunction();
    _getLastErrorMsg = library
        .lookup<NativeFunction<_GetLastErrorMsgNative>>('GetLastErrorMsg')
        .asFunction();
  }

  Future<int?> _findWeixinPid() async {
    final windowPid = _findMainWindowPid();
    if (windowPid != null) return windowPid;

    for (final imageName in ['Weixin.exe', 'WeChat.exe']) {
      final pid = await _findPidByImageName(imageName);
      if (pid != null) return pid;
    }
    return null;
  }

  int? _findMainWindowPid() {
    try {
      final user32 = DynamicLibrary.open('user32.dll');
      final kernel32 = DynamicLibrary.open('kernel32.dll');
      final enumWindows = user32
          .lookup<NativeFunction<_EnumWindowsNative>>('EnumWindows')
          .asFunction<_EnumWindowsDart>();
      _isWindowVisibleForCallback = user32
          .lookup<NativeFunction<_IsWindowVisibleNative>>('IsWindowVisible')
          .asFunction<_IsWindowVisibleDart>();
      _getWindowThreadProcessIdForCallback = user32
          .lookup<NativeFunction<_GetWindowThreadProcessIdNative>>(
            'GetWindowThreadProcessId',
          )
          .asFunction<_GetWindowThreadProcessIdDart>();
      final openProcess = kernel32
          .lookup<NativeFunction<_OpenProcessNative>>('OpenProcess')
          .asFunction<_OpenProcessDart>();
      final queryFullProcessImageName = kernel32
          .lookup<NativeFunction<_QueryFullProcessImageNameNative>>(
            'QueryFullProcessImageNameW',
          )
          .asFunction<_QueryFullProcessImageNameDart>();
      final closeHandle = kernel32
          .lookup<NativeFunction<_CloseHandleNative>>('CloseHandle')
          .asFunction<_CloseHandleDart>();

      _windowProcessIds.clear();
      enumWindows(
        Pointer.fromFunction<_EnumWindowsProcNative>(_enumWindowsProc, 1),
        0,
      );

      for (final pid in _windowProcessIds) {
        final imageName = _queryProcessImageName(
          pid,
          openProcess,
          queryFullProcessImageName,
          closeHandle,
        );
        if (_isWeChatImageName(imageName)) {
          return pid;
        }
      }
    } catch (_) {
      return null;
    } finally {
      _isWindowVisibleForCallback = null;
      _getWindowThreadProcessIdForCallback = null;
      _windowProcessIds.clear();
    }
    return null;
  }

  static int _enumWindowsProc(int hwnd, int lParam) {
    try {
      final isWindowVisible = _isWindowVisibleForCallback;
      final getWindowThreadProcessId = _getWindowThreadProcessIdForCallback;
      if (isWindowVisible == null || getWindowThreadProcessId == null) {
        return 0;
      }
      if (isWindowVisible(hwnd) == 0) return 1;

      final processId = calloc<Uint32>();
      try {
        getWindowThreadProcessId(hwnd, processId);
        if (processId.value > 0) {
          _windowProcessIds.add(processId.value);
        }
      } finally {
        calloc.free(processId);
      }
    } catch (_) {
      return 1;
    }
    return 1;
  }

  String? _queryProcessImageName(
    int pid,
    _OpenProcessDart openProcess,
    _QueryFullProcessImageNameDart queryFullProcessImageName,
    _CloseHandleDart closeHandle,
  ) {
    final handle = openProcess(_processQueryLimitedInformation, 0, pid);
    if (handle == 0) return null;

    final size = calloc<Uint32>();
    final buffer = calloc<Utf16>(32768);
    try {
      size.value = 32768;
      final ok = queryFullProcessImageName(handle, 0, buffer, size);
      if (ok == 0) return null;
      return p.basename(buffer.toDartString());
    } finally {
      calloc.free(buffer);
      calloc.free(size);
      closeHandle(handle);
    }
  }

  Future<int?> _findPidByImageName(String imageName) async {
    final result = await Process.run(
      'tasklist',
      ['/FI', 'IMAGENAME eq $imageName', '/FO', 'CSV', '/NH'],
      runInShell: true,
    );
    if (result.exitCode != 0) return null;
    final output = result.stdout?.toString() ?? '';
    for (final line in const LineSplitter().convert(output)) {
      final columns = _parseCsvLine(line);
      if (columns.length < 2) continue;
      if (columns.first.toLowerCase() != imageName.toLowerCase()) continue;
      return int.tryParse(columns[1]);
    }
    return null;
  }

  bool _isWeChatImageName(String? imageName) {
    final normalized = imageName?.toLowerCase();
    return normalized == 'weixin.exe' || normalized == 'wechat.exe';
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

  void _drainStatusMessages() {
    final getStatusMessage = _getStatusMessage;
    if (getStatusMessage == null) return;

    final buffer = calloc<Int8>(512);
    final level = calloc<Int32>();
    try {
      while (getStatusMessage(buffer, 512, level)) {
        final message = _readNullTerminated(buffer.cast<Uint8>());
        if (message.isNotEmpty) {
          _lastStatusMessage = message;
        }
      }
    } finally {
      calloc.free(buffer);
      calloc.free(level);
    }
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

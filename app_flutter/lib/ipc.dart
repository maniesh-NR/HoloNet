// ipc.dart — JSON-RPC 2.0 client for holonetd (docs/IPC_API.md): NDJSON over
// 127.0.0.1:7977 with the per-install token. The Material You contract:
// `theme.get {osTheme}` → the full M3 role map from the user's seed.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

class HoloIpc {
  Socket? _sock;
  final _events = StreamController<Map<String, dynamic>>.broadcast();
  final String host;
  final int port;
  int _nextId = 100;
  final Map<int, Completer<Map<String, dynamic>>> _pending = {};

  HoloIpc({this.host = '127.0.0.1', this.port = 7977});

  Stream<Map<String, dynamic>> get events => _events.stream;

  Future<void> connect(String token) async {
    _sock = await Socket.connect(host, port, timeout: const Duration(seconds: 5));
    String buffer = '';
    _sock!.listen((data) {
      buffer += utf8.decode(data, allowMalformed: true);
      int nl;
      while ((nl = buffer.indexOf('\n')) >= 0) {
        final line = buffer.substring(0, nl).trim();
        buffer = buffer.substring(nl + 1);
        if (line.isEmpty) continue;
        final msg = jsonDecode(line) as Map<String, dynamic>;
        if (msg['method'] == 'event') {
          _events.add((msg['params'] as Map<String, dynamic>? ?? {}));
        } else {
          final id = msg['id'] as int?;
          if (id != null && _pending.containsKey(id)) {
            _pending.remove(id)!.complete(msg);
          }
        }
      }
    });
    await request('hello', {'token': token});
  }

  Future<Map<String, dynamic>> request(String method, Map<String, dynamic> params) async {
    final id = _nextId++;
    final completer = Completer<Map<String, dynamic>>();
    _pending[id] = completer;
    final req = jsonEncode({'jsonrpc': '2.0', 'id': id, 'method': method, 'params': params});
    _sock!.add(utf8.encode('$req\n'));
    return completer.future.timeout(const Duration(seconds: 30));
  }

  /// The M3 roles for the current seed/mode; `osTheme` reports the system
  /// theme the OS gave us (used when theme_mode == "system").
  Future<Map<String, String>> theme(String osTheme) async {
    final r = await request('theme.get', {'osTheme': osTheme});
    final result = (r['result'] as Map<String, dynamic>? ?? {});
    return result.map((k, v) => MapEntry(k, v.toString()));
  }

  void close() {
    _sock?.destroy();
    _sock = null;
  }
}

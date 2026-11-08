// main.dart — HoloNet Flutter frontend, fully Material You.
//
// Dynamic color strategy (identical across all HoloNet frontends):
//  1. Android 12+ with dynamic color ON → the platform's Monet palette
//     (true wallpaper-derived Material You).
//  2. Otherwise → our own verified Material You engine (material_you.dart,
//     the Dart port of holo-theme) seeded from the user's seed color,
//     persisted in the daemon settings (`seed_color`).
//  3. The daemon's `theme.get` stays authoritative for the seed: changing
//     the seed here updates every HoloNet frontend on every OS.
//
// UI: M3 expressive — large top app bar, NavigationBar, FAB, filled+tonal
// buttons, cards on the surface-container scale, M3 switches, shape scale.
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'ipc.dart';
import 'material_you.dart';

void main() => runApp(const HoloNetApp());

class HoloNetApp extends StatefulWidget {
  const HoloNetApp({super.key});
  @override
  State<HoloNetApp> createState() => _HoloNetAppState();
}

class _HoloNetAppState extends State<HoloNetApp> {
  Brightness _platformBrightness = Brightness.light;
  String _themeMode = 'system'; // system | dark | light
  String _seedHex = '#6750A4';
  bool _dynamicColor = true;
  Map<String, dynamic>? _dynamicDark; // Monet colors (Android 12+)
  Map<String, dynamic>? _dynamicLight;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.platformDispatcher.onPlatformBrightnessChanged = () {
      setState(() {
        _platformBrightness = WidgetsBinding.instance.platformDispatcher.platformBrightness;
      });
    };
    _loadSettings();
    _loadDynamicPalette();
  }

  Future<void> _loadSettings() async {
    // The daemon is the source of truth for the seed (KMP/Qt follow it too).
    // Offline fallback: local engine with the default seed.
    try {
      const token = String.fromEnvironment('HOLONET_TOKEN', defaultValue: '');
      final ipc = HoloIpc();
      await ipc.connect(token);
      final os = _platformBrightness == Brightness.dark ? 'dark' : 'light';
      final roles = await ipc.theme(os);
      setState(() {
        if (roles['_seed'] != null) _seedHex = roles['_seed']!;
        if (roles['_mode'] != null) _themeMode = roles['_mode']!;
        if (roles['_dynamic'] != null) _dynamicColor = roles['_dynamic'] == 'true';
      });
      ipc.close();
    } catch (_) {
      // daemon not running — local Material You still themes the app
    }
  }

  Future<void> _loadDynamicPalette() async {
    try {
      // MethodChannel to the Android wrapper (DynamicColors_MONET); returns
      // null below Android 12 or when dynamic color is unavailable.
      const dyn = MethodChannel('net.holonet.app/dynamiccolor');
      final dark = await dyn.invokeMethod<Map<dynamic, dynamic>?>('dark');
      final light = await dyn.invokeMethod<Map<dynamic, dynamic>?>('light');
      if (mounted) {
        setState(() {
          _dynamicDark = dark?.cast<String, dynamic>();
          _dynamicLight = light?.cast<String, dynamic>();
        });
      }
    } catch (_) {
      // Not Android / no Monet → seeded scheme (identical cross-platform).
    }
  }

  Brightness get _effectiveBrightness {
    switch (_themeMode) {
      case 'dark':
        return Brightness.dark;
      case 'light':
        return Brightness.light;
      default:
        return _platformBrightness;
    }
  }

  ColorScheme _buildScheme(Brightness brightness) {
    // 1. Dynamic color (Monet) when enabled + available.
    if (_dynamicColor) {
      final monet = brightness == Brightness.dark ? _dynamicDark : _dynamicLight;
      if (monet != null && monet['primary'] is int) {
        Color c(String k) => Color(monet[k] as int? ?? 0xFF6750A4);
        return ColorScheme(
          brightness: brightness,
          primary: c('primary'),
          onPrimary: c('onPrimary'),
          primaryContainer: c('primaryContainer'),
          onPrimaryContainer: c('onPrimaryContainer'),
          secondary: c('secondary'),
          onSecondary: c('onSecondary'),
          secondaryContainer: c('secondaryContainer'),
          onSecondaryContainer: c('onSecondaryContainer'),
          tertiary: c('tertiary'),
          onTertiary: c('onTertiary'),
          tertiaryContainer: c('tertiaryContainer'),
          onTertiaryContainer: c('onTertiaryContainer'),
          error: c('error'),
          onError: c('onError'),
          errorContainer: c('errorContainer'),
          onErrorContainer: c('onErrorContainer'),
          surface: c('surface'),
          onSurface: c('onSurface'),
          surfaceContainerHighest: c('surfaceContainerHighest'),
          outline: c('outline'),
          outlineVariant: c('outlineVariant'),
          inverseSurface: c('inverseSurface'),
          onInverseSurface: c('onInverseSurface'),
        );
      }
    }
    // 2. Seeded scheme from OUR engine — byte-identical with KMP + Qt.
    final seed = Argb.fromHex(_seedHex) ?? defaultSeed;
    final mode = brightness == Brightness.dark ? MaterialYouMode.dark : MaterialYouMode.light;
    final s = MaterialYouScheme.fromSeed(seed, mode);
    Color col(Argb a) => Color.fromARGB(a.a, a.r, a.g, a.b);
    return ColorScheme(
      brightness: brightness,
      primary: col(s.primary),
      onPrimary: col(s.onPrimary),
      primaryContainer: col(s.primaryContainer),
      onPrimaryContainer: col(s.onPrimaryContainer),
      secondary: col(s.secondary),
      onSecondary: col(s.onSecondary),
      secondaryContainer: col(s.secondaryContainer),
      onSecondaryContainer: col(s.onSecondaryContainer),
      tertiary: col(s.tertiary),
      onTertiary: col(s.onTertiary),
      tertiaryContainer: col(s.tertiaryContainer),
      onTertiaryContainer: col(s.onTertiaryContainer),
      error: col(s.error),
      onError: col(s.onError),
      errorContainer: col(s.errorContainer),
      onErrorContainer: col(s.onErrorContainer),
      surface: col(s.surface),
      onSurface: col(s.onSurface),
      surfaceContainerHighest: col(s.surfaceContainerHighest),
      outline: col(s.outline),
      outlineVariant: col(s.outlineVariant),
      inverseSurface: col(s.inverseSurface),
      onInverseSurface: col(s.inverseOnSurface),
    );
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'HoloNet',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: _buildScheme(Brightness.light),
        appBarTheme: const AppBarTheme(centerTitle: false),
        cardTheme: const CardTheme(elevation: 0),
      ),
      darkTheme: ThemeData(
        useMaterial3: true,
        colorScheme: _buildScheme(Brightness.dark),
        appBarTheme: const AppBarTheme(centerTitle: false),
        cardTheme: const CardTheme(elevation: 0),
      ),
      themeMode: _themeMode == 'system'
          ? ThemeMode.system
          : (_themeMode == 'dark' ? ThemeMode.dark : ThemeMode.light),
      home: HomeScreen(
        seedHex: _seedHex,
        dynamicColor: _dynamicColor,
        themeMode: _themeMode,
        onThemeChanged: (mode, seed, dyn) async {
          setState(() {
            _themeMode = mode;
            _seedHex = seed;
            _dynamicColor = dyn;
          });
          try {
            const token = String.fromEnvironment('HOLONET_TOKEN', defaultValue: '');
            final ipc = HoloIpc();
            await ipc.connect(token);
            await ipc.request('settings.set', {
              'values': {
                'theme_mode': mode,
                'seed_color': seed,
                'dynamic_color': dyn ? 'true' : 'false',
              }
            });
            ipc.close();
          } catch (_) {}
        },
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Home (connect) with M3 expressive widgets
// ---------------------------------------------------------------------------

class HomeScreen extends StatefulWidget {
  final String seedHex;
  final bool dynamicColor;
  final String themeMode;
  final Future<void> Function(String mode, String seed, bool dyn) onThemeChanged;
  const HomeScreen({
    super.key,
    required this.seedHex,
    required this.dynamicColor,
    required this.themeMode,
    required this.onThemeChanged,
  });

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  int _navIndex = 0;
  String _state = 'disconnected';
  List<Map<String, dynamic>> _profiles = [];
  String? _error;

  @override
  void initState() {
    super.initState();
    _boot();
  }

  Future<void> _boot() async {
    try {
      const token = String.fromEnvironment('HOLONET_TOKEN', defaultValue: '');
      final ipc = HoloIpc();
      await ipc.connect(token);
      ipc.events.listen((ev) {
        if (ev['name'] == 'state.changed') {
          setState(() => _state = (ev['payload'] as Map<String, dynamic>)['state'] ?? _state);
        }
      });
      await _refresh(ipc);
      _ipc = ipc;
    } catch (e) {
      setState(() => _error = 'daemon unreachable: $e');
    }
  }

  HoloIpc? _ipc;

  Future<void> _refresh(HoloIpc? ipc) async {
    ipc ??= _ipc;
    if (ipc == null) return;
    final st = await ipc.request('state.get', {});
    final res = st['result'] as Map<String, dynamic>? ?? {};
    final lst = await ipc.request('profiles.list', {});
    final profiles = ((lst['result'] as Map<String, dynamic>? ?? {})['profiles'] as List? ?? [])
        .map((e) => Map<String, dynamic>.from(e as Map))
        .toList();
    setState(() {
      _state = res['state'] ?? _state;
      _profiles = profiles;
    });
  }

  Future<void> _toggle() async {
    if (_state == 'connected') {
      await _ipc?.request('session.disconnect', {});
    } else if (_profiles.isNotEmpty) {
      await _ipc?.request('session.connect', {'profileId': _profiles.first['id']});
    } else {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Import or add a server first')),
        );
      }
      return;
    }
    await _refresh(null);
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final pages = [
      _connectPage(cs),
      _serversPage(cs),
      _themePage(cs),
    ];
    return Scaffold(
      body: CustomScrollView(
        slivers: [
          // M3 large top app bar (collapses on scroll).
          SliverAppBar.large(
            title: const Text('HoloNet'),
            actions: [
              IconButton(
                tooltip: 'Material You',
                icon: const Icon(Icons.palette_outlined),
                onPressed: () => setState(() => _navIndex = 2),
              ),
            ],
          ),
          SliverToBoxAdapter(
            child: _error != null
                ? Padding(
                    padding: const EdgeInsets.all(24),
                    child: Card(
                      color: cs.errorContainer,
                      child: Padding(
                        padding: const EdgeInsets.all(16),
                        child: Row(children: [
                          Icon(Icons.error_outline, color: cs.onErrorContainer),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Text(_error!, style: TextStyle(color: cs.onErrorContainer)),
                          ),
                        ]),
                      ),
                    ),
                  )
                : pages[_navIndex],
          ),
        ],
      ),
      // M3 navigation bar.
      bottomNavigationBar: NavigationBar(
        selectedIndex: _navIndex,
        onDestinationSelected: (i) => setState(() => _navIndex = i),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.shield_outlined), selectedIcon: Icon(Icons.shield), label: 'Home'),
          NavigationDestination(icon: Icon(Icons.dns_outlined), selectedIcon: Icon(Icons.dns), label: 'Servers'),
          NavigationDestination(icon: Icon(Icons.palette_outlined), selectedIcon: Icon(Icons.palette), label: 'Theme'),
        ],
      ),
      // M3 FAB (extended while disconnected).
      floatingActionButton: _navIndex == 0
          ? FloatingActionButton.extended(
              onPressed: _toggle,
              icon: const Icon(Icons.power_settings_new),
              label: Text(_state == 'connected' ? 'Disconnect' : 'Connect'),
            )
          : null,
    );
  }

  Widget _connectPage(ColorScheme cs) {
    final connected = _state == 'connected';
    return Padding(
      padding: const EdgeInsets.fromLTRB(24, 8, 24, 96),
      child: Column(
        children: [
          // The connect orb — M3 shape scale (extra-large), state-tinted.
          Semantics(
            button: true,
            label: 'Toggle connection',
            child: Material(
              color: connected ? cs.primaryContainer : cs.surfaceContainerHighest,
              shape: const CircleBorder(),
              child: InkWell(
                customBorder: const CircleBorder(),
                onTap: _toggle,
                child: SizedBox(
                  width: 184,
                  height: 184,
                  child: Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(
                          connected ? Icons.shield : Icons.shield_outlined,
                          size: 56,
                          color: connected ? cs.onPrimaryContainer : cs.onSurfaceVariant,
                        ),
                        const SizedBox(height: 8),
                        Text(
                          _state.toUpperCase(),
                          style: Theme.of(context).textTheme.titleMedium?.copyWith(
                                color: connected ? cs.onPrimaryContainer : cs.onSurfaceVariant,
                              ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ),
          const SizedBox(height: 24),
          // Active profile card on the container scale.
          if (_profiles.isNotEmpty)
            Card(
              color: cs.surfaceContainerLow,
              child: ListTile(
                leading: Icon(Icons.vpn_key_outlined, color: cs.primary),
                title: Text('${_profiles.first['name']}'),
                subtitle: Text('${_profiles.first['driver']} · ${_profiles.first['source']}'),
                trailing: Icon(Icons.chevron_right, color: cs.onSurfaceVariant),
                onTap: () => setState(() => _navIndex = 1),
              ),
            ),
          const SizedBox(height: 16),
          Text(
            'Material You · ${widget.dynamicColor ? "dynamic palette" : "seeded ${widget.seedHex}"}',
            style: Theme.of(context).textTheme.labelMedium?.copyWith(color: cs.onSurfaceVariant),
          ),
        ],
      ),
    );
  }

  Widget _serversPage(ColorScheme cs) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 0, 16, 96),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Servers', style: Theme.of(context).textTheme.headlineSmall),
          const SizedBox(height: 8),
          FilledButton.tonalIcon(
            onPressed: () async {
              // Import from clipboard.
              final data = await Clipboard.getData('text/plain');
              if (data?.text != null && data!.text!.isNotEmpty) {
                await _ipc?.request('configs.import', {'kind': 'auto', 'data': data.text});
                await _refresh(null);
              }
            },
            icon: const Icon(Icons.content_paste),
            label: const Text('Import from clipboard'),
          ),
          const SizedBox(height: 12),
          ..._profiles.map(
            (p) => Card(
              color: cs.surfaceContainerLow,
              child: ListTile(
                leading: Icon(Icons.language, color: cs.tertiary),
                title: Text('${p['name']}'),
                subtitle: Text('${p['driver']} · ${p['server']}:${p['port']}'),
                trailing: IconButton(
                  icon: const Icon(Icons.play_arrow),
                  onPressed: () async {
                    await _ipc?.request('session.connect', {'profileId': p['id']});
                    await _refresh(null);
                    setState(() => _navIndex = 0);
                  },
                ),
              ),
            ),
          ),
          if (_profiles.isEmpty)
            Padding(
              padding: const EdgeInsets.all(24),
              child: Text(
                'No servers yet — import a link (ss://, vmess://, vless://, trojan://, hysteria2://…) or ask a provider.',
                style: TextStyle(color: cs.onSurfaceVariant),
              ),
            ),
        ],
      ),
    );
  }

  // The Material You control page: theme mode, dynamic color, seed picker.
  Widget _themePage(ColorScheme cs) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 0, 16, 96),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Material You', style: Theme.of(context).textTheme.headlineSmall),
          const SizedBox(height: 4),
          Text(
            'One seed colors every HoloNet surface — on every OS.',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
          ),
          const SizedBox(height: 16),
          // Theme mode segmented control.
          Card(
            color: cs.surfaceContainerLow,
            child: Column(
              children: [
                ListTile(
                  leading: const Icon(Icons.brightness_auto),
                  title: const Text('Follow system'),
                  trailing: Radio<String>(
                    value: 'system',
                    groupValue: widget.themeMode,
                    onChanged: (v) => widget.onThemeChanged(v!, widget.seedHex, widget.dynamicColor),
                  ),
                ),
                ListTile(
                  leading: const Icon(Icons.light_mode),
                  title: const Text('Light'),
                  trailing: Radio<String>(
                    value: 'light',
                    groupValue: widget.themeMode,
                    onChanged: (v) => widget.onThemeChanged(v!, widget.seedHex, widget.dynamicColor),
                  ),
                ),
                ListTile(
                  leading: const Icon(Icons.dark_mode),
                  title: const Text('Dark'),
                  trailing: Radio<String>(
                    value: 'dark',
                    groupValue: widget.themeMode,
                    onChanged: (v) => widget.onThemeChanged(v!, widget.seedHex, widget.dynamicColor),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),
          // Dynamic color switch (Android 12+ wallpaper palette).
          Card(
            color: cs.surfaceContainerLow,
            child: SwitchListTile(
              secondary: const Icon(Icons.wallpaper),
              title: const Text('Dynamic color (wallpaper)'),
              subtitle: const Text('Android 12+; otherwise the seed applies'),
              value: widget.dynamicColor,
              onChanged: (v) => widget.onThemeChanged(widget.themeMode, widget.seedHex, v),
            ),
          ),
          const SizedBox(height: 12),
          // Seed picker: curated Material palette + custom hex.
          Card(
            color: cs.surfaceContainerLow,
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Seed color', style: Theme.of(context).textTheme.titleMedium),
                  const SizedBox(height: 12),
                  Wrap(
                    spacing: 12,
                    runSpacing: 12,
                    children: [
                      for (final hex in [
                        '#6750A4', '#B3261E', '#0061A4', '#006E1C', '#7D5260',
                        '#8C4E00', '#6750A4', '#006493', '#984061', '#3F6978',
                      ])
                        _SeedSwatch(
                          hex: hex,
                          selected: widget.seedHex.toUpperCase() == hex.toUpperCase(),
                          onTap: () => widget.onThemeChanged(widget.themeMode, hex, widget.dynamicColor),
                        ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  Row(
                    children: [
                      Expanded(
                        child: OutlinedButton.icon(
                          onPressed: () async {
                            final controller = TextEditingController(text: widget.seedHex);
                            final hex = await showDialog<String>(
                              context: context,
                              builder: (ctx) => AlertDialog(
                                title: const Text('Custom seed'),
                                content: TextField(
                                  controller: controller,
                                  decoration: const InputDecoration(hintText: '#RRGGBB', border: OutlineInputBorder()),
                                ),
                                actions: [
                                  TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
                                  FilledButton(onPressed: () => Navigator.pop(ctx, controller.text), child: const Text('Apply')),
                                ],
                              ),
                            );
                            if (hex != null && Argb.fromHex(hex) != null) {
                              await widget.onThemeChanged(widget.themeMode, hex, widget.dynamicColor);
                            }
                          },
                          icon: const Icon(Icons.edit),
                          label: const Text('Custom hex'),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _SeedSwatch extends StatelessWidget {
  final String hex;
  final bool selected;
  final VoidCallback onTap;
  const _SeedSwatch({required this.hex, required this.selected, required this.onTap});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final color = Color(_parseHex(hex));
    return Semantics(
      button: true,
      selected: selected,
      label: 'Seed $hex',
      child: InkWell(
        onTap: onTap,
        customBorder: const CircleBorder(),
        child: Container(
          width: 48,
          height: 48,
          decoration: BoxDecoration(
            color: color,
            shape: BoxShape.circle,
            border: selected ? Border.all(color: cs.primary, width: 3) : null,
          ),
          child: selected ? Icon(Icons.check, color: _onColor(color)) : null,
        ),
      ),
    );
  }

  static int _parseHex(String h) {
    var s = h.replaceFirst('#', '');
    if (s.length == 6) s = 'FF$s';
    return int.tryParse(s, radix: 16) ?? 0xFF6750A4;
  }

  static Color _onColor(Color c) => c.computeLuminance() > 0.5 ? Colors.black : Colors.white;
}

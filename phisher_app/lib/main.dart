import 'dart:io' show Platform;
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';

void main() {
  runApp(const PhishingDetectionApp());
}

class PhishingDetectionApp extends StatelessWidget {
  const PhishingDetectionApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      home: const SplashScreen(),
      theme: ThemeData(
        fontFamily: 'Poppins',
        useMaterial3: true,
      ),
    );
  }
}

String getServerBase() {
  if (kIsWeb) {
    return "http://localhost:3000"; // web build
  } else if (Platform.isAndroid) {
    return "http://10.0.2.2:3000"; // Android emulator
  } else if (Platform.isWindows || Platform.isLinux || Platform.isMacOS) {
    return "http://127.0.0.1:3000"; // Desktop
  } else if (Platform.isIOS) {
    return "http://localhost:3000"; // iOS simulator
  }
  return "http://127.0.0.1:3000"; // fallback
}

class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen> {
  @override
  void initState() {
    super.initState();
    Future.delayed(const Duration(seconds: 2), () {
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(
          builder: (context) => PhishingDetectionScreen(),
        ),
      );
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.deepPurple,
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Image.asset('assests/images/phishguard_logo.png', height: 100),
            const SizedBox(height: 20),
            const Text(
              "PhishGuard",
              style: TextStyle(
                color: Colors.white,
                fontSize: 36,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 10),
            const Text(
              "Secure Your Digital Waters",
              style: TextStyle(
                color: Colors.white,
                fontSize: 16,
                fontStyle: FontStyle.italic,
              ),
            ),
            const SizedBox(height: 50),
            const CircularProgressIndicator(
              valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
            ),
          ],
        ),
      ),
    );
  }
}

class PhishingDetectionScreen extends StatefulWidget {
  @override
  _PhishingDetectionScreenState createState() =>
      _PhishingDetectionScreenState();
}

class _PhishingDetectionScreenState extends State<PhishingDetectionScreen> {
  final TextEditingController _urlController = TextEditingController();
  String? verdict;
  double? confidence;
  List<String>? reasons;
  bool loading = false;

  Future<void> _checkUrl() async {
    final url = _urlController.text.trim();
    if (url.isEmpty) return;

    setState(() {
      loading = true;
      verdict = null;
      reasons = null;
    });

    try {
      final serverBase = getServerBase();
      final uri = Uri.parse('$serverBase/api/check?url=$url');
      final res =
      await http.get(uri).timeout(const Duration(seconds: 8));

      if (res.statusCode == 200) {
        final data = json.decode(res.body);
        setState(() {
          verdict = data['verdict'];
          confidence = (data['confidence'] as num).toDouble();
          reasons = List<String>.from(data['reasons']);
        });
      } else {
        setState(() {
          verdict = "error";
          reasons = ["Server error: ${res.statusCode}"];
        });
      }
    } catch (e) {
      setState(() {
        verdict = "error";
        reasons = ["Error connecting to server: $e"];
      });
    } finally {
      setState(() {
        loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.grey[100],
      appBar: AppBar(
        title: const Text(
          "Phishing Detection Tool",
          style: TextStyle(
            fontFamily: 'Poppins',
            fontWeight: FontWeight.w600,
            fontStyle: FontStyle.italic,
            fontSize: 20,
            color: Colors.white,
          ),
        ),
        backgroundColor: Colors.deepPurple,
        centerTitle: true,
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          children: [
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _urlController,
                    decoration: InputDecoration(
                      prefixIcon: const Icon(Icons.link),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                      labelText: "Enter URL",
                    ),
                  ),
                ),
                const SizedBox(width: 10),
                ElevatedButton.icon(
                  onPressed: _checkUrl,
                  icon: const Icon(Icons.search, color: Colors.white),
                  label: const Text("Check URL",
                      style: TextStyle(color: Colors.white)),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.deepPurple,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 20),
            if (loading) const CircularProgressIndicator(),
            if (!loading && verdict != null)
              Card(
                elevation: 3,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(16),
                ),
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        "Analysis Results",
                        style: TextStyle(
                          fontSize: 20,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const Divider(),
                      Row(
                        children: [
                          const Icon(Icons.language, color: Colors.blue),
                          const SizedBox(width: 8),
                          Text("URL: ${_urlController.text}"),
                        ],
                      ),
                      const SizedBox(height: 12),
                      Row(
                        children: [
                          const Icon(Icons.verified, color: Colors.black54),
                          const SizedBox(width: 8),
                          const Text("Verdict: "),
                          Chip(
                            label: Text(verdict!),
                            backgroundColor: verdict == "safe"
                                ? Colors.green
                                : verdict == "suspicious"
                                ? Colors.orange
                                : Colors.red,
                          ),
                        ],
                      ),
                      if (confidence != null) ...[
                        const SizedBox(height: 12),
                        Row(
                          children: [
                            const Icon(Icons.shield,
                                color: Colors.deepPurple),
                            const SizedBox(width: 8),
                            Text(
                                "Confidence: ${(confidence! * 100).toStringAsFixed(1)}%"),
                          ],
                        ),
                      ],
                      const SizedBox(height: 20),
                      const Text(
                        "Detected Issues",
                        style: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const Divider(),
                      if (reasons != null && reasons!.isNotEmpty)
                        Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: reasons!
                              .map((r) => Row(
                            children: [
                              const Icon(Icons.error,
                                  size: 16, color: Colors.red),
                              const SizedBox(width: 6),
                              Expanded(child: Text(r)),
                            ],
                          ))
                              .toList(),
                        )
                      else
                        const Text("No issues detected."),
                    ],
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

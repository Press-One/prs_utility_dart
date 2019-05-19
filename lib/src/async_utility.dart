import 'dart:isolate';

class AsyncUtility {
  static execute(Function(List<dynamic>) func, List<dynamic> parameters) async {
    final response = new ReceivePort();
    Isolate.spawn(_isolate, response.sendPort);
    final sendPort = await response.first as SendPort;
    final answer = new ReceivePort();
    sendPort.send([func, parameters, answer.sendPort]);
    return answer.first;
  }

  static void _isolate(SendPort initialReplyTo) async {
    final port = new ReceivePort();
    initialReplyTo.send(port.sendPort);
    port.listen((message) {
      final func = message[0] as Function(List<dynamic>);
      final parameters = message[1] as List<dynamic>;
      final send = message[2] as SendPort;
      send.send(func(parameters));
    });
  }
}

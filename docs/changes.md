# Change Log

## 1.4.0:
* Refactor FakeNet-NG to unify Windows and Linux packet handling
* Remove Proxy Listener UDP stream abstraction to prevent issue where
  subsequent clients do not receive response packets because the proxy listener
  continues to send them to the old (expired) ephemeral port for the previous
  client
* Stop flag command-line support for rudimentary IPC-based start/stop
  automation
* Integration test script for MultiHost and SingleHost mode
* Fixed Errno 98 (`TIME_WAIT`) issue with `RawTcpListener`
* WinDivert `GetLastError` exception work-around for [WinDivert issue
  #32](https://github.com/ffalcinelli/pydivert/issues/32)

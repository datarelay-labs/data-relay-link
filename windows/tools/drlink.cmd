@echo off
REM drlink.cmd — canonical Data Relay Link Windows CLI identity (wraps frp-client.cmd)
REM DRLINK-PRODUCT-SHIM — ownership marker: uninstall removes only launchers carrying it.
"%~dp0frp-client.cmd" %*

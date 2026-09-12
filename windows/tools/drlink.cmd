@echo off
REM drlink.cmd — canonical Data Relay Link Windows CLI identity (wraps frp-client.cmd)
"%~dp0frp-client.cmd" %*

@echo off
powershell -NoLogo -NoProfile -Command "Start-Process PowerShell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""C:\ad_health.ps1""'"

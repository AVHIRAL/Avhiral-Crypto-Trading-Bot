@echo off
title AVHIRAL BOT CRYPTO COINBASE V7.8 OFF
color 0a
cls
echo Attendez que le programme demarre...
echo.
echo Vous devrez peut-etre fournir des informations d'identification administrateur.
echo.
echo Appuyez sur une touche pour continuer...
pause >nul
cd /d %~dp0
if not "%1"=="am_admin" (powershell start -verb runas '%0' am_admin & exit /b)
echo.
echo Demarrage du programme...
echo.
python AVHIRAL_BOT_CRYPTO_COINBASE_V7.8_OFF.py
echo.
echo Appuyez sur une touche pour fermer la fenetre...
pause >nul
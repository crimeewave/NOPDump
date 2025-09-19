@echo off

echo Building!
echo Building NOPDump GUI...
echo Make sure you placed patterns.json with .exe!
pyinstaller --onefile --noconsole main2.py
echo Builded!
echo Building NOPDump...
pyinstaller main.py
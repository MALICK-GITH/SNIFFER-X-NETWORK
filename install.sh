#!/data/data/com.termux/files/usr/bin/bash
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
mkdir -p "$PREFIX/lib/sxnetwork"
cp "$ROOT/src/sxnetwork.py" "$PREFIX/lib/sxnetwork/sxnetwork.py"
cat > "$PREFIX/bin/sxn" <<'EOF'
#!/data/data/com.termux/files/usr/bin/sh
exec python "$PREFIX/lib/sxnetwork/sxnetwork.py" "$@"
EOF
chmod +x "$PREFIX/bin/sxn"
printf '\nSNIFFER-X-NETWORK installed.\nRun: sxn\n'

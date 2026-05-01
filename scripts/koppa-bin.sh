#!/bin/bash
if command -v python3 &>/dev/null; then
  if python3 -c "import koppa" 2>/dev/null; then
    exec python3 -m koppa "$@"
  fi
  if [ -f /usr/share/koppa/src/koppa.py ]; then
    exec python3 /usr/share/koppa/src/koppa.py "$@"
  fi
fi
echo "KOPPA not found. Run: pip3 install koppa-lang"
exit 1


rlv - Rancher Logs Viewer
=========================
A k9s-style terminal UI for browsing and analysing the output of the Rancher
logs-collector (rancher2_logs_collector.sh) completely offline.

python3 rlv.py <bundle-dir | bundle.tar.gz | dir-with-many-tarballs>
    python3 rlv.py <bundle> --summary
    python3 rlv.py <bundle> --issues
    python3 rlv.py <bundle> -c "get pods -A | grep -i crash" -c "grep -i x509"

Inside the TUI press :  to run a command,?  for help. Press Esc to go back to the previous screen. 

#Pure Python 3.8+ standard library (curses: Linux/macOS; on Windows `pip install windows-curses`).

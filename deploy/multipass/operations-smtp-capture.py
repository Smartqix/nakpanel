#!/usr/bin/env python3
"""Owned-guest, loopback-only SMTP fault fixture. Never relays messages."""
import argparse,json,socketserver,time
from pathlib import Path

class Capture(socketserver.StreamRequestHandler):
 def handle(self):
  self.connection.settimeout(20);self.wfile.write(b'220 operations fixture\r\n');recipient=''
  while True:
   line=self.rfile.readline(8192)
   if not line:return
   verb=line.split(b' ',1)[0].strip().upper()
   if verb in (b'EHLO',b'HELO',b'MAIL',b'RSET',b'NOOP'):self.wfile.write(b'250 OK\r\n')
   elif verb==b'RCPT':recipient=line.decode('ascii',errors='replace').strip();self.wfile.write(b'250 OK\r\n')
   elif verb==b'DATA':
    self.wfile.write(b'354 continue\r\n');size=0
    while True:
     part=self.rfile.readline(8192)
     if not part:return
     if part==b'.\r\n':break
     size+=len(part)
     if size>1024*1024:raise ValueError('fixture message limit exceeded')
    accepted=(self.server.state/'mode').read_text().strip()=='accept'
    with (self.server.state/'receipts.jsonl').open('a') as stream:stream.write(json.dumps(dict(accepted=accepted,recipient=recipient,size=size,at=time.time()))+'\n')
    self.wfile.write(b'250 accepted\r\n' if accepted else b'451 fixture rejection\r\n');self.wfile.flush()
    # Positive DATA followed by a disconnected QUIT must stay accepted.
    if accepted:return
   elif verb==b'QUIT':self.wfile.write(b'221 bye\r\n');return
   else:self.wfile.write(b'500 unknown command\r\n')

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--state-dir',required=True);args=parser.parse_args()
 state=Path(args.state_dir);state.mkdir(mode=0o700,parents=True,exist_ok=True)
 with socketserver.TCPServer(('127.0.0.1',2525),Capture) as server:server.state=state;server.serve_forever()

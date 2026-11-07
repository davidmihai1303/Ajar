import socket
import threading

TELNET_BANNER: bytes = b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27"
FTP_BANNER: bytes = b"220 (vsFTPd 2.3.4)\r\n"


def serve(port: int, banner: bytes) -> None:
    srv: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    print(f"[fake] listening on {port}")
    while True:
        conn: socket.socket
        conn, _ = srv.accept()
        try:
            conn.sendall(banner)
        finally:
            conn.close()


threading.Thread(target=serve, args=(2323, TELNET_BANNER), daemon=True).start()
threading.Thread(target=serve, args=(2121, FTP_BANNER), daemon=True).start()
threading.Event().wait()

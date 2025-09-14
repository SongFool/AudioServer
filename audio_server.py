import socket
import time
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import scrolledtext
import queue

# ----- 协议常量 -----
WIFI_PACK_HEAD = 0xAA55
WIFI_PACK_END  = 0x55AA
TIMEOUT        = 3
MAX_RETRIES    = 3
MAX_WORKERS    = 10
CHUNK_SIZE     = 1024

# ----- 工具函数 -----
def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"

def calculate_checksum(data: bytes) -> int:
    checksum = 0
    for b in data:
        checksum = (checksum + b) & 0xFFFF
    return checksum

# ----- 数据包 -----
class WiFiPacket:
    def __init__(self, data: bytes | None = None):
        self.head = WIFI_PACK_HEAD
        self.len  = len(data) if data else 0
        self.data = data or b""
        self.check = 0
        self.end  = WIFI_PACK_END
        if data:
            self.calculate_check()

    def calculate_check(self):
        data_to_check = struct.pack("<HH", self.head, self.len) + self.data
        self.check = calculate_checksum(data_to_check)

    def to_bytes(self) -> bytes:
        return struct.pack("<HH", self.head, self.len) + self.data + struct.pack("<H", self.check) + struct.pack("<H", self.end)

# ----- 文件服务器 -----
class FileTransferServer:
    def __init__(self, file_path: str, log_func, port: int = 50011, max_workers: int = MAX_WORKERS):
        self.file_path   = file_path
        self.port        = port
        self.host        = get_local_ip()
        self.max_workers = max_workers
        self.log         = log_func

        self._file_data: bytes | None = None
        self._server_sock: socket.socket | None = None
        self._executor: ThreadPoolExecutor | None = None
        self._stop_event = threading.Event()
        self._stop_lock  = threading.Lock()

    def start(self):
        if not self._load_file():
            return

        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind((self.host, self.port))
            self._server_sock.listen()
            self._server_sock.settimeout(1.0)
            self.log(f"服务器启动，监听 {self.host}:{self.port}")
        except OSError as e:
            self.log(f"服务器启动失败: {e}")
            self._safe_close_server_socket()
            return

        self._executor = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="FTS")

        try:
            while not self._stop_event.is_set():
                try:
                    conn, addr = self._server_sock.accept()
                except socket.timeout:
                    continue
                except OSError as e:
                    if self._stop_event.is_set():
                        break
                    self.log(f"accept 出错: {e}")
                    continue
                try:
                    self._executor.submit(self._handle_client, conn, addr)
                except RuntimeError as e:
                    self.log(f"提交任务失败（线程池已关闭？）: {e}")
                    try: conn.close()
                    except: pass
        except Exception as e:
            self.log(f"服务器异常: {e}")
        finally:
            self.stop()

    def stop(self):
        with self._stop_lock:
            if self._stop_event.is_set():
                return
            self._stop_event.set()
            self._safe_close_server_socket()
            if self._executor:
                try:
                    self._executor.shutdown(wait=True, cancel_futures=False)
                except Exception as e:
                    self.log(f"线程池关闭异常: {e}")
                finally:
                    self._executor = None
            self.log("服务器已停止")

    def _safe_close_server_socket(self):
        if self._server_sock:
            try: self._server_sock.close()
            except: pass
            finally: self._server_sock = None

    def _load_file(self) -> bool:
        try:
            with open(self.file_path, "rb") as f:
                self._file_data = f.read()
            self.log(f"加载文件成功: {self.file_path}, 大小={len(self._file_data)} 字节")
            return True
        except Exception as e:
            self.log(f"读取文件失败: {e}")
            return False

    def _wait_for_ack(self, conn: socket.socket) -> bool:
        prev_timeout = conn.gettimeout()
        conn.settimeout(TIMEOUT)
        try:
            data = conn.recv(1024)
            if data and data.startswith(b"OK"):
                return True
            self.log(f"[线程{threading.get_ident()}] 收到无效ACK: {data!r}")
            return False
        except socket.timeout:
            self.log(f"[线程{threading.get_ident()}] 等待ACK超时")
            return False
        except Exception as e:
            self.log(f"[线程{threading.get_ident()}] 等待ACK出错: {e}")
            return False
        finally:
            try: conn.settimeout(prev_timeout)
            except: pass

    def _send_packet_with_retry(self, conn: socket.socket, packet: WiFiPacket) -> bool:
        packet_bytes = packet.to_bytes()
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                conn.sendall(packet_bytes)
                if self._wait_for_ack(conn):
                    return True
            except Exception as e:
                self.log(f"[线程{threading.get_ident()}] 发送数据包出错: {e}")
            if attempt < MAX_RETRIES:
                self.log(f"[线程{threading.get_ident()}] 重试 {attempt}/{MAX_RETRIES - 1} ...")
                time.sleep(0.3)
        self.log(f"[线程{threading.get_ident()}] 达到最大重试次数，发送失败")
        return False

    def _send_file_as_packets(self, conn: socket.socket) -> bool:
        assert self._file_data is not None
        file_size = len(self._file_data)
        offset = 0
        pkt_idx = 0
        while offset < file_size:
            remaining = file_size - offset
            take = min(CHUNK_SIZE, remaining)
            chunk = bytearray(self._file_data[offset:offset + take])
            if len(chunk) < CHUNK_SIZE:
                chunk.extend(b"\xFF" * (CHUNK_SIZE - len(chunk)))
            packet = WiFiPacket(bytes(chunk))
            if not self._send_packet_with_retry(conn, packet):
                return False
            offset += CHUNK_SIZE
            pkt_idx += 1
            self.log(f"[线程{threading.get_ident()}] [{conn.fileno()}] 进度: {offset}/{file_size} ({pkt_idx} 包)")
        try:
            conn.sendall(b"EOF")
            self.log(f"[线程{threading.get_ident()}] [{conn.fileno()}] 文件发送完成")
            return True
        except Exception as e:
            conn.sendall(b"ERROR")
            self.log(f"[线程{threading.get_ident()}] 结束包发送失败: {e}")
            return False

    def _handle_client(self, conn: socket.socket, addr):
        try:
            self.log(f"[线程{threading.get_ident()}] 新连接: {addr}")
            conn.settimeout(30.0)
            self.log(f"[线程{threading.get_ident()}] 等待客户端命令...")
            command_data = conn.recv(1024)
            if not command_data:
                self.log(f"[线程{threading.get_ident()}] {addr} 客户端断开（未发送命令）")
                return
            command = command_data.decode("utf-8", errors="ignore").strip()
            self.log(f"[线程{threading.get_ident()}] 收到命令: {command}")
            if command.lower() == "get":
                self.log(f"[线程{threading.get_ident()}] {addr} 请求下载文件，开始下发数据...")
                ok = self._send_file_as_packets(conn)
                if not ok:
                    self.log(f"[线程{threading.get_ident()}] {addr} 文件发送失败/中断")
            else:
                self.log(f"[线程{threading.get_ident()}] {addr} 收到未知命令: {command}")
                try: 
                    conn.sendall(b"ERROR: unknown command")
                except: 
                    pass
        except Exception as e:
            self.log(f"[线程{threading.get_ident()}] {addr} 处理异常: {e}")
        finally:
            try: 
                conn.shutdown(socket.SHUT_RDWR)
            except: 
                pass
            try: 
                conn.close()
            except: 
                pass
            self.log(f"[线程{threading.get_ident()}] 连接关闭: {addr}")

# ----- GUI -----
class ServerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("文件传输服务器")
        self.geometry("700x500")
        self.file_path = "output_big_endian.bin"
        self.server: FileTransferServer | None = None
        self.server_thread: threading.Thread | None = None

        self.log_queue = queue.Queue()

        tk.Label(self, text="服务器信息:").pack(anchor="w", padx=10, pady=5)
        self.info_text = tk.Text(self, height=3, state="disabled")
        self.info_text.pack(fill="x", padx=10)

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=5)
        self.start_btn = tk.Button(btn_frame, text="启动服务器", command=self.start_server)
        self.start_btn.pack(side="left", padx=10)
        self.stop_btn = tk.Button(btn_frame, text="停止服务器", command=self.stop_server, state="disabled")
        self.stop_btn.pack(side="left", padx=10)

        tk.Label(self, text="日志:").pack(anchor="w", padx=10, pady=5)
        self.log_area = scrolledtext.ScrolledText(self, height=20, state="disabled")
        self.log_area.pack(fill="both", expand=True, padx=10, pady=5)

        self.update_server_info()
        self.after(100, self.update_log_area)

    def log(self, message: str):
        self.log_queue.put(message)

    def update_log_area(self):
        while not self.log_queue.empty():
            msg = self.log_queue.get()
            self.log_area.config(state="normal")
            self.log_area.insert(tk.END, msg + "\n")
            self.log_area.see(tk.END)
            self.log_area.config(state="disabled")
        self.after(100, self.update_log_area)

    def update_server_info(self):
        ip = get_local_ip()
        size = 0
        try:
            with open(self.file_path, "rb") as f:
                size = len(f.read())
        except: pass
        self.info_text.config(state="normal")
        self.info_text.delete("1.0", tk.END)
        self.info_text.insert(tk.END, f"IP地址: {ip}\n")
        self.info_text.insert(tk.END, f"端口号: 50011\n")
        self.info_text.insert(tk.END, f"文件大小: {size} 字节\n")
        self.info_text.config(state="disabled")

    def start_server(self):
        if self.server_thread and self.server_thread.is_alive():
            self.log("服务器已在运行")
            return
        self.server = FileTransferServer(self.file_path, log_func=self.log, port=50011)
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.log("服务器启动线程已启动")

    def stop_server(self):
        if self.server:
            self.server.stop()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.log("已发送停止服务器指令")

if __name__ == "__main__":
    gui = ServerGUI()
    gui.mainloop()

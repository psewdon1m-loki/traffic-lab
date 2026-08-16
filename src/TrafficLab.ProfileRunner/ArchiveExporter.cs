using System.Runtime.InteropServices;

internal static class ArchiveExporter
{
    private static readonly Guid DownloadsFolderId = new("374DE290-123F-4565-9164-39C4925E467B");

    public static string GetDefaultExportDirectory()
    {
        if (OperatingSystem.IsWindows())
        {
            var knownDownloads = TryGetKnownDownloadsFolder();
            if (!string.IsNullOrWhiteSpace(knownDownloads)) return knownDownloads;
        }

        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(profile)) return Path.Combine(profile, "Downloads");
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        return string.IsNullOrWhiteSpace(documents) ? AppContext.BaseDirectory : documents;
    }

    public static async Task<string> CopyToDirectoryAsync(string sourcePath, string destinationDirectory, CancellationToken cancellationToken = default)
    {
        var source = Path.GetFullPath(sourcePath ?? throw new ArgumentNullException(nameof(sourcePath)));
        if (!File.Exists(source)) throw new FileNotFoundException("Result archive was not found.", source);
        if (!string.Equals(Path.GetExtension(source), ".zip", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Only a ZIP result archive can be exported.");

        var destination = Path.GetFullPath(destinationDirectory ?? throw new ArgumentNullException(nameof(destinationDirectory)));
        Directory.CreateDirectory(destination);
        var temporary = Path.Combine(destination, $".traffic-lab-export-{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            await using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await input.CopyToAsync(output, 64 * 1024, cancellationToken);
                await output.FlushAsync(cancellationToken);
                if (output.Length != input.Length) throw new IOException("Exported archive length does not match the source archive.");
            }

            var stem = Path.GetFileNameWithoutExtension(source);
            var extension = Path.GetExtension(source);
            for (var suffix = 0; suffix < 10_000; suffix++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var fileName = suffix == 0 ? stem + extension : $"{stem} ({suffix}){extension}";
                var candidate = Path.Combine(destination, fileName);
                try
                {
                    File.Move(temporary, candidate, overwrite: false);
                    return candidate;
                }
                catch (IOException) when (File.Exists(candidate))
                {
                    // Preserve earlier exports and retry with a unique suffix.
                }
            }
            throw new IOException("Could not allocate a unique result archive name in the export folder.");
        }
        finally
        {
            try { if (File.Exists(temporary)) File.Delete(temporary); } catch { }
        }
    }

    private static string? TryGetKnownDownloadsFolder()
    {
        IntPtr pointer = IntPtr.Zero;
        try
        {
            var folder = DownloadsFolderId;
            return SHGetKnownFolderPath(ref folder, 0, IntPtr.Zero, out pointer) == 0
                ? Marshal.PtrToStringUni(pointer)
                : null;
        }
        catch
        {
            return null;
        }
        finally
        {
            if (pointer != IntPtr.Zero) Marshal.FreeCoTaskMem(pointer);
        }
    }

    [DllImport("shell32.dll")]
    private static extern int SHGetKnownFolderPath(ref Guid folderId, uint flags, IntPtr token, out IntPtr path);
}

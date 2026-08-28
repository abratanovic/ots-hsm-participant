namespace MedSign.Api.Signing;

public static class DotEnv
{
    public static Dictionary<string, string> Read(string path)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);

        if (!File.Exists(path))
        {
            return values;
        }

        foreach (var line in File.ReadAllLines(path))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('#'))
            {
                continue;
            }

            var separator = trimmed.IndexOf('=');
            if (separator > 0)
            {
                values[trimmed[..separator].Trim()] = trimmed[(separator + 1)..].Trim();
            }
        }

        return values;
    }

    public static void Write(string path, string key, string value, string? comment = null)
    {
        var lines = File.Exists(path) ? File.ReadAllLines(path).ToList() : [];
        var replaced = false;

        for (var i = 0; i < lines.Count; i++)
        {
            if (lines[i].TrimStart().StartsWith($"{key}=", StringComparison.Ordinal))
            {
                lines[i] = $"{key}={value}";
                replaced = true;
                break;
            }
        }

        if (!replaced)
        {
            if (lines.Count > 0)
            {
                lines.Add(string.Empty);
            }

            if (comment is not null)
            {
                lines.AddRange(comment.Split('\n').Select(part => $"# {part}"));
            }

            lines.Add($"{key}={value}");
        }

        File.WriteAllLines(path, lines);
    }
}

<#
.SYNOPSIS
  Draws the PC Health app icon at every size Windows uses (each size drawn natively, so it stays sharp)
  and writes assets\icon-<size>.png plus assets\pchealth.ico (16-256 px).
#>
Add-Type -AssemblyName System.Drawing
$dir = Join-Path $PSScriptRoot 'assets'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$sizes = 16, 20, 24, 32, 40, 48, 64, 96, 128, 256

function New-IconBitmap([int]$s) {
    $bmp = New-Object System.Drawing.Bitmap($s, $s, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'; $g.PixelOffsetMode = 'HighQuality'; $g.InterpolationMode = 'HighQualityBicubic'
    $g.Clear([System.Drawing.Color]::Transparent)

    # rounded square, blue -> teal
    $m = [single]($s * 0.03); $w = [single]($s - 2 * $m); $r = [single]($s * 0.24)
    $bg = New-Object System.Drawing.Drawing2D.GraphicsPath
    $bg.AddArc($m, $m, $r, $r, 180, 90); $bg.AddArc($m + $w - $r, $m, $r, $r, 270, 90)
    $bg.AddArc($m + $w - $r, $m + $w - $r, $r, $r, 0, 90); $bg.AddArc($m, $m + $w - $r, $r, $r, 90, 90); $bg.CloseFigure()
    $rect = New-Object System.Drawing.RectangleF($m, $m, $w, $w)
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, [System.Drawing.Color]::FromArgb(255, 52, 120, 246), [System.Drawing.Color]::FromArgb(255, 18, 206, 184), 55)
    $g.FillPath($grad, $bg)
    # soft top highlight
    $g.SetClip($bg)
    $hi = New-Object System.Drawing.Drawing2D.LinearGradientBrush((New-Object System.Drawing.RectangleF($m, [single]($m - 1), $w, [single]($w + 2))), [System.Drawing.Color]::FromArgb(60, 255, 255, 255), [System.Drawing.Color]::FromArgb(0, 255, 255, 255), 90)
    $g.FillRectangle($hi, $m - 1, $m - 1, $w + 2, $w + 2)
    $g.ResetClip()

    # white shield
    function P($x, $y) { New-Object System.Drawing.PointF([single]($x * $s), [single]($y * $s)) }
    $sh = New-Object System.Drawing.Drawing2D.GraphicsPath
    $sh.AddLine((P 0.5 0.16), (P 0.80 0.27))
    $sh.AddLine((P 0.80 0.27), (P 0.80 0.52))
    $sh.AddBezier((P 0.80 0.52), (P 0.80 0.69), (P 0.64 0.79), (P 0.5 0.85))
    $sh.AddBezier((P 0.5 0.85), (P 0.36 0.79), (P 0.20 0.69), (P 0.20 0.52))
    $sh.AddLine((P 0.20 0.52), (P 0.20 0.27))
    $sh.CloseFigure()
    if ($s -ge 32) {   # subtle shadow under the shield for depth
        $shadow = New-Object System.Drawing.Drawing2D.Matrix; $shadow.Translate(0, [single]($s * 0.018))
        $sp = $sh.Clone(); $sp.Transform($shadow)
        $g.FillPath((New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(55, 0, 30, 90))), $sp)
    }
    $g.FillPath((New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)), $sh)

    # check mark
    $pw = [single][math]::Max(1.6, $s * 0.085)
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 36, 112, 232), $pw)
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
    $g.DrawLines($pen, [System.Drawing.PointF[]]@((P 0.355 0.505), (P 0.46 0.61), (P 0.655 0.385)))
    $g.Dispose()
    return $bmp
}

$pngs = @{}
foreach ($s in $sizes) {
    $bmp = New-IconBitmap $s
    $ms = New-Object IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngs[$s] = $ms.ToArray()
    [IO.File]::WriteAllBytes((Join-Path $dir "icon-$s.png"), $pngs[$s])
    $bmp.Dispose(); $ms.Dispose()
}

# .ico with PNG-compressed images
$fs = [IO.File]::Open((Join-Path $dir 'pchealth.ico'), 'Create')
$bw = New-Object IO.BinaryWriter($fs)
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
foreach ($s in $sizes) {
    $wh = if ($s -ge 256) { [byte]0 } else { [byte]$s }
    $bw.Write($wh); $bw.Write($wh); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32); $bw.Write([uint32]$pngs[$s].Length); $bw.Write([uint32]$offset)
    $offset += $pngs[$s].Length
}
foreach ($s in $sizes) { $bw.Write($pngs[$s]) }
$bw.Close(); $fs.Close()
Write-Host "Icon written to $dir" -ForegroundColor Green

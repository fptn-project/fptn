"""Draws fptn-vless.ico (blue rounded square with white "tunnel" rings).

Pure standard library, run by CMake at configure time:
    python gen_icon.py <output.ico>
"""
import struct
import sys
import zlib


def pixel(x, y, n):
    """RGBA of the icon at (x, y) in [0, n)^2, 3x3 anti-aliasing."""
    r_acc = g_acc = b_acc = a_acc = 0
    for sy in range(3):
        for sx in range(3):
            fx = (x + (sx + 0.5) / 3) / n
            fy = (y + (sy + 0.5) / 3) / n
            px, py = fx - 0.5, fy - 0.5
            # rounded square
            r = 0.22
            qx, qy = abs(px) - (0.5 - r), abs(py) - (0.5 - r)
            ox, oy = max(qx, 0.0), max(qy, 0.0)
            if (ox * ox + oy * oy) ** 0.5 > r:
                continue
            col = (47, 111, 237)
            d = (px * px + py * py) ** 0.5
            if abs(d - 0.36) <= 0.0375 or abs(d - 0.22) <= 0.03 or d <= 0.075:
                col = (255, 255, 255)
            r_acc += col[0]
            g_acc += col[1]
            b_acc += col[2]
            a_acc += 1
    if a_acc == 0:
        return (0, 0, 0, 0)
    return (r_acc // a_acc, g_acc // a_acc, b_acc // a_acc, a_acc * 255 // 9)


def png(n):
    rows = bytearray()
    for y in range(n):
        rows.append(0)
        for x in range(n):
            rows.extend(pixel(x, y, n))

    def chunk(kind, data):
        body = kind + data
        return (struct.pack(">I", len(data)) + body +
                struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF))

    return (b"\x89PNG\r\n\x1a\n" +
            chunk(b"IHDR", struct.pack(">IIBBBBB", n, n, 8, 6, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(bytes(rows), 9)) +
            chunk(b"IEND", b""))


def main(path):
    sizes = [16, 32, 48, 256]
    images = [png(n) for n in sizes]
    out = bytearray(struct.pack("<HHH", 0, 1, len(sizes)))
    offset = 6 + 16 * len(sizes)
    for n, data in zip(sizes, images):
        out += struct.pack("<BBBBHHII", n % 256, n % 256, 0, 0, 1, 32,
                           len(data), offset)
        offset += len(data)
    for data in images:
        out += data
    with open(path, "wb") as f:
        f.write(out)


if __name__ == "__main__":
    main(sys.argv[1])

"""Connection profiles offered by the bot. Descriptions are honest about
trade-offs: none of these can guarantee undetectability."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    key: str
    title: str
    emoji: str
    summary: str
    description: str
    limitations: str
    network: str      # tcp | ws | grpc
    security: str     # none | tls
    cipher: str
    padding: str      # "min-max" handshake padding bytes
    keepalive: int    # seconds, 0 = off
    use_cdn: bool     # route through Cloudflare (WS+TLS :443)


PROFILES: dict[str, Profile] = {
    "strong_dpi": Profile(
        key="strong_dpi", title="DPI قوی", emoji="🛡",
        summary="شرایط دشوار؛ WS+TLS پشت Cloudflare، پدینگ زیاد",
        description=(
            "ترافیک KILLDPI داخل WebSocket روی TLS 1.3 و از طریق Cloudflare عبور می‌کند. "
            "اثرانگشت TLS کروم (uTLS) استفاده می‌شود، هندشیک با پدینگ تصادفی بزرگ (256–1024 بایت) "
            "پوشانده می‌شود و در صورت پروب فعال، سرور به یک وب‌سایت واقعی fallback می‌کند."),
        limitations=(
            "• تأخیر بالاتر (۲ لایه رمزنگاری + CDN)\n"
            "• سرعت به ظرفیت Cloudflare محدود است\n"
            "• UDP داخل تونل TCP حمل می‌شود (برای بازی ایده‌آل نیست)\n"
            "• هیچ روشی شناسایی‌ناپذیریِ کامل را تضمین نمی‌کند"),
        network="ws", security="tls", cipher="chacha20-poly1305", padding="256-1024", keepalive=25, use_cdn=True),
    "gaming": Profile(
        key="gaming", title="Gaming", emoji="🎮",
        summary="کمترین تأخیر؛ TCP+TLS مستقیم، پدینگ کم",
        description=(
            "اتصال مستقیم به سرور (بدون CDN) روی TCP+TLS. هر دیتاگرام UDP بازی داخل یک فریم "
            "رمزشده با مرز حفظ‌شده حمل می‌شود. پدینگ کم و keep-alive کوتاه برای پایداری NAT. "
            "AES-256-GCM (سریع‌تر روی CPUهای با شتاب‌دهنده AES)."),
        limitations=(
            "• IP سرور مستقیماً دیده می‌شود؛ در صورت مسدودشدن باید سرور عوض شود\n"
            "• UDP روی TCP حمل می‌شود؛ در شبکه با packet loss بالا، head-of-line blocking ممکن است\n"
            "• پدینگ کم = مقاومت کمتر در برابر تحلیل آماری"),
        network="tcp", security="tls", cipher="aes-256-gcm", padding="16-64", keepalive=15, use_cdn=False),
    "web": Profile(
        key="web", title="Web Browsing", emoji="🌐",
        summary="وب‌گردی روزمره؛ WS+TLS با Cloudflare، متعادل",
        description="WebSocket روی TLS از طریق Cloudflare با پدینگ متوسط؛ مناسب مرورگر و اپ‌های روزمره.",
        limitations=(
            "• برای استریم سنگین یا دانلود بزرگ، سرعت به CDN وابسته است\n"
            "• برای بازی مناسب نیست (تأخیر CDN)"),
        network="ws", security="tls", cipher="chacha20-poly1305", padding="64-512", keepalive=30, use_cdn=True),
    "general": Profile(
        key="general", title="General", emoji="⚖️",
        summary="متعادل؛ TCP+TLS مستقیم، پدینگ پیش‌فرض",
        description="اتصال مستقیم TCP+TLS با اثرانگشت کروم، پدینگ پیش‌فرض (64–512) و keep-alive. گزینهٔ خوب برای شروع.",
        limitations=(
            "• IP سرور مستقیماً دیده می‌شود\n"
            "• اگر شبکه شما TLS مستقیم به IP ناشناس را محدود می‌کند، «DPI قوی» را امتحان کنید"),
        network="tcp", security="tls", cipher="chacha20-poly1305", padding="64-512", keepalive=30, use_cdn=False),
}

PROFILE_ORDER = ["strong_dpi", "gaming", "web", "general"]

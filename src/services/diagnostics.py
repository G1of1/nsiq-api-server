import psutil


BYTES_PER_GIGABYTE = 1024**3


def get_system_stats():
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return {
        "cpu_usage": f"{psutil.cpu_percent(interval=1):.2f}%",
        "memory": (
            f"{memory.used / BYTES_PER_GIGABYTE:.0f}GB/"
            f"{memory.total / BYTES_PER_GIGABYTE:.2f}GB"
        ),
        "disk": f"{disk.percent:.0f}%",
    }
import subprocess

def obtener_ips_activas():
    proceso = subprocess.run(["powershell", "-File", "MostrarIPs.ps1"], capture_output=True, text=True)
    salida = proceso.stdout.strip()
    if salida:
        # dividir por espacios además de saltos de línea
        return [ip.strip() for linea in salida.splitlines() for ip in linea.split() if ip.strip()]
    return []

def main():
    print("Obteniendo IPs activas desde PowerShell...\n")
    ips = obtener_ips_activas()
    for ip in ips:
        print(ip)

if __name__ == "__main__":
    main()

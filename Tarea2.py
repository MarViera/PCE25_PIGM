import subprocess
import requests

API_KEY = 'd2355d03d9feff0470a4dc72e739ad028c5c9b309a4abbf9e1f0cda4c8f8d42f1d66fda25f83bc0a'
API_URL = 'https://api.abuseipdb.com/api/v2/check'

def obtener_ips_activas():
    print("Ejecutando script de PowerShell para obtener IPs activas...")
    resultado = subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-File", "MostrarIPs.ps1"],
        capture_output=True, text=True
    )
    if resultado.returncode != 0:
        print("Error al ejecutar el script:", resultado.stderr)
        return []

    salida = resultado.stdout.strip()
    print("\nListado de IPs encontradas:")
    print(salida if salida else "No se encontró ninguna IP.")
    
    return [ip.strip() for ip in salida.splitlines() if ip.strip()]

def checar_ip(ip):
    resp = requests.get(API_URL, headers={
        'Accept': 'application/json',
        'Key': API_KEY
    }, params={
        'ipAddress': ip,
        'maxAgeInDays': '90'
    })

    if resp.status_code != 200:
        return f"Error al consultar IP {ip}: {resp.status_code} - {resp.text}"

    data = resp.json()['data']
    return (f"\nInformación de la IP {ip}:\n"
            f"- País: {data.get('countryCode', 'Desconocido')}\n"
            f"- ISP: {data.get('isp', 'Desconocido')}\n"
            f"- Reportes: {data['totalReports']}\n"
            f"- Confianza en abuso: {data['abuseConfidenceScore']}%\n")

def main():
    ips = obtener_ips_activas()
    if not ips:
        print("No se encontraron IPs.")
        return

    print("\nConsultando máximo 3 IPs en AbuseIPDB...\n")
    for ip in ips[:3]:
        print(checar_ip(ip))

if __name__ == "__main__":
    main()

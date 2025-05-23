import subprocess
import requests
from datetime import datetime
import argparse

API_KEY = 'd2355d03d9feff0470a4dc72e739ad028c5c9b309a4abbf9e1f0cda4c8f8d42f1d66fda25f83bc0a'
API_URL = 'https://api.abuseipdb.com/api/v2/check'
LOG_FILE = 'log_ips.txt'

def registrar_log(texto):
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(texto + '\n')

def obtener_ips_activas():
    print("Ejecutando script de PowerShell para obtener IPs activas...")
    resultado = subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-File", "MostrarIPs.ps1"],
        capture_output=True, text=True
    )
    if resultado.returncode != 0:
        error_msg = f"Error al ejecutar el script: {resultado.stderr}"
        print(error_msg)
        registrar_log(error_msg)
        return []

    salida = resultado.stdout.strip()
    print("\nListado de IPs encontradas:")
    print(salida if salida else "No se encontró ninguna IP.")
    
    ips = [ip.strip() for ip in salida.splitlines() if ip.strip()]
    registrar_log("IPs detectadas:\n" + "\n".join(ips) + "\n")
    return ips

def checar_ip(ip):
    resp = requests.get(API_URL, headers={
        'Accept': 'application/json',
        'Key': API_KEY
    }, params={
        'ipAddress': ip,
        'maxAgeInDays': '90'
    })

    if resp.status_code != 200:
        error = f"Error al consultar IP {ip}: {resp.status_code} - {resp.text}"
        registrar_log(error)
        return error

    data = resp.json()['data']
    score = data['abuseConfidenceScore']
    resultado = (f"\nInformación de la IP {ip}:\n"
                 f"- País: {data.get('countryCode', 'Desconocido')}\n"
                 f"- ISP: {data.get('isp', 'Desconocido')}\n"
                 f"- Reportes: {data['totalReports']}\n"
                 f"- Confianza en abuso: {score}%\n"
                 f"- {'Maliciosa' if score >= 50 else 'No maliciosa'}\n")

    registrar_log(resultado)
    return resultado

def main():
    parser = argparse.ArgumentParser(description='Consulta de IPs en AbuseIPDB')
    parser.add_argument('ips', nargs='*', help='Lista opcional de IPs para consultar')
    args = parser.parse_args()

    fecha_actual = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    registrar_log(f"\n===== EJECUCIÓN DEL SCRIPT: {fecha_actual} =====")

    if args.ips:
        ips = args.ips
        print(f"IPs recibidas desde argumentos: {ips}")
    else:
        ips = obtener_ips_activas()

    if not ips:
        print("No se encontraron IPs.")
        registrar_log("No se encontraron IPs.\n")
        return

    print("\nConsultando máximo 3 IPs en AbuseIPDB...\n")
    for ip in ips[:3]:
        resultado = checar_ip(ip)
        print(resultado)

if __name__ == "__main__":
    main()

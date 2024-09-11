from flask import Flask, render_template, request, flash
from urllib.parse import urlparse
import requests
import ssl

app = Flask(__name__)
app.secret_key = '1c'  # Necesario para que funcionen los mensajes flash

# Función que detecta señales de phishing
def check_phishing(url):
    reasons = []
    try:
        parsed_url = urlparse(url)
        
        # 1. URL sospechosa
        if parsed_url.scheme != 'https':
            reasons.append("No usa HTTPS.")
        
        if "@" in parsed_url.netloc or parsed_url.netloc.count('.') < 1:
            reasons.append("El dominio parece sospechoso.")

        # 2. Solicitudes inusuales de información (búsqueda básica en la URL)
        if any(keyword in url.lower() for keyword in ['login', 'password', 'secure', 'account', 'creditcard']):
            reasons.append("La URL contiene palabras sospechosas que indican una solicitud de información sensible.")
        
        # 3. Contenido o diseño inusual (búsqueda de patrones básicos en la página)
        try:
            response = requests.get(url)
            if response.status_code != 200:
                reasons.append("El sitio no cargó correctamente, lo que puede indicar problemas de diseño o contenido.")
            if "<img" not in response.text:
                reasons.append("No se encontraron imágenes en la página, lo cual es inusual.")
            if "<title>" in response.text and parsed_url.netloc.split(".")[1] not in response.text.lower():
                reasons.append("El título de la página no coincide con el dominio, lo cual es sospechoso.")
        except Exception:
            reasons.append("No se pudo acceder al contenido del sitio.")
        
        # 4. Comportamiento extraño del navegador (ventanas emergentes o scripts)
        if 'window.open' in response.text or 'popup' in response.text:
            reasons.append("El sitio contiene ventanas emergentes, lo cual puede ser un comportamiento sospechoso.")
        
        # 5. Solicitudes urgentes o amenazas (búsqueda de palabras clave en el contenido)
        urgent_keywords = ['urgente', 'acción inmediata', 'verifica tu cuenta', 'rápido', 'inmediatamente']
        if any(word in response.text.lower() for word in urgent_keywords):
            reasons.append("El contenido del sitio contiene mensajes de urgencia que pueden ser señales de phishing.")
        
        # 6. Verificación de certificados (básico)
        try:
            requests.get(url, verify=True)
        except ssl.SSLError:
            reasons.append("El certificado SSL del sitio no es válido o está mal configurado.")
    
    except Exception:
        reasons.append("La URL es inválida o no se pudo procesar.")
    
    return reasons

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    try:
        num_urls = int(request.form['numUrls'])
    except KeyError:
        flash("Error: no se seleccionó la cantidad de URLs.")
        return render_template('index.html')
    
    results = []

    for i in range(1, num_urls + 1):
        url_key = f'url{i}'
        try:
            url = request.form[url_key]
        except KeyError:
            flash(f"Error: No se proporcionó la URL {i}.")
            return render_template('index.html')

        reasons = check_phishing(url)
        if reasons:
            results.append(f"La página {url} se detectó como phishing. Razones: " + ", ".join(reasons))
        else:
            results.append(f"La página {url} es segura. No hay riesgos de phishing.")

    # Unimos los resultados para mostrar todo en una sola cadena
    message = "<br>".join(results)

    return render_template('index.html', message=message)

if __name__ == '__main__':
    app.run(debug=True)
